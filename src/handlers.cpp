/**
 * @file handlers.cpp
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "json_parse_utils.h"

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
}

#include "handlers.h"
#include "log.h"
#include "subscriber_data_manager.h"
#include "ifchandler.h"
#include "registration_utils.h"
#include "stack.h"
#include "pjutils.h"
#include "sproutsasevent.h"
#include "uri_classifier.h"
#include "sprout_xml_utils.h"

// If we can't find the AoR pair in the current SDM, we will either use the
// backup_aor_pair or we will try and look up the AoR pair in the remote SDMs.
// Therefore either the backup_aor_pair should be NULL, or remote_sdms should be empty.
static bool sdm_access_common(AoRPair** aor_pair,
                              std::string aor_id,
                              SubscriberDataManager* current_sdm,
                              std::vector<SubscriberDataManager*> remote_sdms,
                              AoRPair* backup_aor_pair,
                              SAS::TrailId trail)
{
  // Find the current bindings for the AoR.
  delete *aor_pair;
  *aor_pair = current_sdm->get_aor_data(aor_id, trail);
  TRC_DEBUG("Retrieved AoR data %p", *aor_pair);

  if ((*aor_pair == NULL) ||
      ((*aor_pair)->get_current() == NULL))
  {
    // Failed to get data for the AoR because there is no connection
    // to the store.
    TRC_ERROR("Failed to get AoR binding for %s from store", aor_id.c_str());
    return false;
  }

  // If we don't have any bindings, try the backup AoR and/or stores.
  if ((*aor_pair)->get_current()->bindings().empty())
  {
    bool found_binding = false;
    bool backup_aor_pair_alloced = false;

    if ((backup_aor_pair != NULL) &&
        (backup_aor_pair->current_contains_bindings()))
    {
      found_binding = true;
    }
    else
    {
      std::vector<SubscriberDataManager*>::iterator it = remote_sdms.begin();
      AoRPair* local_backup_aor_pair = NULL;

      while ((it != remote_sdms.end()) && (!found_binding))
      {
        if ((*it)->has_servers())
        {
          local_backup_aor_pair = (*it)->get_aor_data(aor_id, trail);

          if ((local_backup_aor_pair != NULL) &&
              (local_backup_aor_pair->current_contains_bindings()))
          {
            found_binding = true;
            backup_aor_pair = local_backup_aor_pair;

            // Flag that we have allocated the memory for the backup pair so
            // that we can tidy it up later.
            backup_aor_pair_alloced = true;
          }
        }

        if (!found_binding)
        {
          ++it;

          if (local_backup_aor_pair != NULL)
          {
            delete local_backup_aor_pair;
            local_backup_aor_pair = NULL;
          }
        }
      }
    }

    if (found_binding)
    {
      (*aor_pair)->get_current()->copy_subscriptions_and_bindings(backup_aor_pair->get_current());
    }

    if (backup_aor_pair_alloced)
    {
      delete backup_aor_pair;
      backup_aor_pair = NULL;
    }
  }

  return true;
}

static bool get_reg_data(HSSConnection* hss,
                         std::string aor_id,
                         AssociatedURIs& associated_uris,
                         std::map<std::string, Ifcs>& ifc_map,
                         SAS::TrailId trail)
{
  std::string state;
  std::vector<std::string> unbarred_irs_impus;
  HTTPCode http_code = hss->get_registration_data(aor_id,
                                                  state,
                                                  ifc_map,
                                                  associated_uris,
                                                  trail);

  unbarred_irs_impus = associated_uris.get_unbarred_uris();

  if ((http_code != HTTP_OK) || unbarred_irs_impus.empty())
  {
    // We were unable to determine the set of IMPUs for this AoR. Push the AoR
    // we have into the Associated URIs list so that we have at least one IMPU
    // we can issue NOTIFYs for. We should only do this if that IMPU is not barred.
    TRC_WARNING("Unable to get Implicit Registration Set for %s: %d", aor_id.c_str(), http_code);
    if (!associated_uris.is_impu_barred(aor_id))
    {
      associated_uris.clear_uris();
      associated_uris.add_uri(aor_id, false);
    }
  }

  return (http_code == HTTP_OK);
}

static void report_sip_all_register_marker(SAS::TrailId trail, std::string uri_str)
{
  // Parse the SIP URI and get the username from it.
  pj_pool_t* tmp_pool = pj_pool_create(&stack_data.cp.factory, "handlers", 1024, 512, NULL);
  pjsip_uri* uri = PJUtils::uri_from_string(uri_str, tmp_pool);

  if (uri != NULL)
  {
    pj_str_t user = PJUtils::user_from_uri(uri);

    // Create and report the marker.
    SAS::Marker sip_all_register(trail, MARKER_ID_SIP_ALL_REGISTER, 1u);
    sip_all_register.add_var_param(PJUtils::strip_uri_scheme(uri_str));
    // Add the DN parameter. If the user part is not numeric just log it in
    // its entirety.
    sip_all_register.add_var_param(URIClassifier::is_user_numeric(user) ?
                                   PJUtils::remove_visual_separators(user) :
                                   PJUtils::pj_str_to_string(&user));
    SAS::report_marker(sip_all_register);
  }
  else
  {
    TRC_WARNING("Could not raise SAS REGISTER marker for unparseable URI '%s'", uri_str.c_str());
  }

  // Remember to release the temporary pool.
  pj_pool_release(tmp_pool);
}

void DeregistrationTask::run()
{
  // HTTP method must be a DELETE
  if (_req.method() != htp_method_DELETE)
  {
    TRC_WARNING("HTTP method isn't delete");
    send_http_reply(HTTP_BADMETHOD);
    delete this;
    return;
  }

  // Mandatory query parameter 'send-notifications' that must be true or false
  _notify = _req.param("send-notifications");

  if (_notify != "true" && _notify != "false")
  {
    TRC_WARNING("Mandatory send-notifications param is missing or invalid, send 400");
    send_http_reply(HTTP_BAD_REQUEST);
    delete this;
    return;
  }

  // Parse the JSON body
  HTTPCode rc = parse_request(_req.get_rx_body());

  if (rc != HTTP_OK)
  {
    TRC_WARNING("Request body is invalid, send %d", rc);
    send_http_reply(rc);
    delete this;
    return;
  }

  rc = handle_request();

  send_http_reply(rc);
  delete this;
}

void AoRTimeoutTask::process_aor_timeout(std::string aor_id)
{
  bool all_bindings_expired = false;
  TRC_DEBUG("Handling timer pop for AoR id: %s", aor_id.c_str());

  // Determine the set of IMPUs in the Implicit Registration Set
  AssociatedURIs associated_uris = {};
  std::map<std::string, Ifcs> ifc_map;
  get_reg_data(_cfg->_hss, aor_id, associated_uris, ifc_map, trail());

  AoRPair* aor_pair = set_aor_data(_cfg->_sdm,
                                   aor_id,
                                   &associated_uris,
                                   NULL,
                                   _cfg->_remote_sdms,
                                   all_bindings_expired);

  if (aor_pair != NULL)
  {
    // If we have any remote stores, try to store this in them too.  We don't worry
    // about failures in this case.
    // LCOV_EXCL_START
    for (std::vector<SubscriberDataManager*>::const_iterator sdm = _cfg->_remote_sdms.begin();
         sdm != _cfg->_remote_sdms.end();
         ++sdm)
    {
      if ((*sdm)->has_servers())
      {
        bool ignored;
        AoRPair* remote_aor_pair = set_aor_data(*sdm,
                                                aor_id,
                                                &associated_uris,
                                                aor_pair,
                                                {},
                                                ignored);
        delete remote_aor_pair;
      }
    }
    // LCOV_EXCL_STOP

    if (all_bindings_expired)
    {
      TRC_DEBUG("All bindings have expired based on an AoR Timeout - triggering deregistration at the HSS");
      SAS::Event event(trail(), SASEvent::REGISTRATION_EXPIRED, 0);
      event.add_var_param(aor_id);
      SAS::report_event(event);

      // Get the S-CSCF URI off the AoR to put on the SAR.
      AoR* aor = aor_pair->get_current();

      _cfg->_hss->update_registration_state(aor_id, "", HSSConnection::DEREG_TIMEOUT, aor->_scscf_uri, trail());
    }
    else
    {
      SAS::Event event(trail(), SASEvent::SOME_BINDINGS_EXPIRED, 0);
      event.add_var_param(aor_id);
      SAS::report_event(event);
    }
  }
  else
  {
    // We couldn't update the SubscriberDataManager but there is nothing else we can do to
    // recover from this.
    TRC_INFO("Could not update SubscriberDataManager on registration timeout for AoR: %s",
             aor_id.c_str());
  }

  delete aor_pair;
  report_sip_all_register_marker(trail(), aor_id);
}

AoRPair* AoRTimeoutTask::set_aor_data(
                          SubscriberDataManager* current_sdm,
                          std::string aor_id,
                          AssociatedURIs* associated_uris,
                          AoRPair* previous_aor_pair,
                          std::vector<SubscriberDataManager*> remote_sdms,
                          bool& all_bindings_expired)
{
  AoRPair* aor_pair = NULL;
  Store::Status set_rc;

  do
  {
    if (!sdm_access_common(&aor_pair,
                           aor_id,
                           current_sdm,
                           remote_sdms,
                           previous_aor_pair,
                           trail()))
    {
      break;
    }

    aor_pair->get_current()->_associated_uris = *associated_uris;

    set_rc = current_sdm->set_aor_data(aor_id,
                                       aor_pair,
                                       trail(),
                                       all_bindings_expired);
    if (set_rc != Store::OK)
    {
      delete aor_pair; aor_pair = NULL;
    }
  }
  while (set_rc == Store::DATA_CONTENTION);

  return aor_pair;
}


// Retrieve the aors and any private IDs from the request body
HTTPCode DeregistrationTask::parse_request(std::string body)
{
  rapidjson::Document doc;
  doc.Parse<0>(body.c_str());

  if (doc.HasParseError())
  {
    TRC_INFO("Failed to parse data as JSON: %s\nError: %s",
             body.c_str(),
             rapidjson::GetParseError_En(doc.GetParseError()));
    return HTTP_BAD_REQUEST;
  }

  try
  {
    JSON_ASSERT_CONTAINS(doc, "registrations");
    JSON_ASSERT_ARRAY(doc["registrations"]);
    const rapidjson::Value& reg_arr = doc["registrations"];

    for (rapidjson::Value::ConstValueIterator reg_it = reg_arr.Begin();
         reg_it != reg_arr.End();
         ++reg_it)
    {
      try
      {
        std::string primary_impu;
        std::string impi = "";
        JSON_GET_STRING_MEMBER(*reg_it, "primary-impu", primary_impu);

        if (((*reg_it).HasMember("impi")) &&
            ((*reg_it)["impi"].IsString()))
        {
          impi = (*reg_it)["impi"].GetString();
        }

        _bindings.insert(std::make_pair(primary_impu, impi));
      }
      catch (JsonFormatError err)
      {
        TRC_WARNING("Invalid JSON - registration doesn't contain primary-impu");
        return HTTP_BAD_REQUEST;
      }
    }
  }
  catch (JsonFormatError err)
  {
    TRC_INFO("Registrations not available in JSON");
    return HTTP_BAD_REQUEST;
  }

  TRC_DEBUG("HTTP request successfully parsed");
  return HTTP_OK;
}

HTTPCode DeregistrationTask::handle_request()
{
  std::set<std::string> impis_to_delete;

  for (std::map<std::string, std::string>::iterator it=_bindings.begin();
       it!=_bindings.end();
       ++it)
  {
    AoRPair* aor_pair = deregister_bindings(_cfg->_sdm,
                                            _cfg->_hss,
                                            _cfg->_fifc_service,
                                            _cfg->_ifc_configuration,
                                            it->first,
                                            it->second,
                                            NULL,
                                            _cfg->_remote_sdms,
                                            impis_to_delete);

    // LCOV_EXCL_START
    if ((aor_pair != NULL) &&
        (aor_pair->get_current() != NULL))
    {
      // If we have any remote stores, try to store this in them too.  We don't worry
      // about failures in this case.
      for (std::vector<SubscriberDataManager*>::const_iterator sdm = _cfg->_remote_sdms.begin();
           sdm != _cfg->_remote_sdms.end();
           ++sdm)
      {
        if ((*sdm)->has_servers())
        {
          AoRPair* remote_aor_pair = deregister_bindings(*sdm,
                                                         _cfg->_hss,
                                                         _cfg->_fifc_service,
                                                         _cfg->_ifc_configuration,
                                                         it->first,
                                                         it->second,
                                                         aor_pair,
                                                         {},
                                                         impis_to_delete);
          delete remote_aor_pair;
        }
      }
    }
    // LCOV_EXCL_STOP
    else
    {
      // Can't connect to memcached, return 500. If this isn't the first AoR being edited
      // then this will lead to an inconsistency between the HSS and Sprout, as
      // Sprout will have changed some of the AoRs, but HSS will believe they all failed.
      // Sprout accepts changes to AoRs that don't exist though.
      TRC_WARNING("Unable to connect to memcached for AoR %s", it->first.c_str());

      delete aor_pair;
      return HTTP_SERVER_ERROR;
    }

    delete aor_pair;
  }

  // Delete IMPIs from the store.
  for(std::set<std::string>::iterator impi = impis_to_delete.begin();
      impi != impis_to_delete.end();
      ++impi)
  {
    TRC_DEBUG("Delete %s from the IMPI store(s)", impi->c_str());

    delete_impi_from_store(_cfg->_local_impi_store, *impi);
    for (ImpiStore* store: _cfg->_remote_impi_stores)
    {
      delete_impi_from_store(store, *impi);
    }
  }

  return HTTP_OK;
}

void DeregistrationTask::delete_impi_from_store(ImpiStore* store,
                                                const std::string& impi)
{
  Store::Status store_rc = Store::OK;
  ImpiStore::Impi* impi_obj = NULL;

  do
  {
    // Free any IMPI we had from the last loop iteration.
    delete impi_obj; impi_obj = NULL;

    impi_obj = store->get_impi(impi, _trail);

    if (impi_obj != NULL)
    {
      store_rc = store->delete_impi(impi_obj, _trail);
    }
  }
  while ((impi_obj != NULL) && (store_rc == Store::DATA_CONTENTION));

  delete impi_obj; impi_obj = NULL;
}


AoRPair* DeregistrationTask::deregister_bindings(
                             SubscriberDataManager* current_sdm,
                             HSSConnection* hss,
                             FIFCService* fifc_service,
                             IFCConfiguration ifc_configuration,
                             std::string aor_id,
                             std::string private_id,
                             AoRPair* previous_aor_pair,
                             std::vector<SubscriberDataManager*> remote_sdms,
                             std::set<std::string>& impis_to_delete)
{
  AoRPair* aor_pair = NULL;
  bool all_bindings_expired = false;
  bool got_ifcs;
  Store::Status set_rc;
  std::vector<std::string> impis_to_dereg;

  // Get registration data
  AssociatedURIs associated_uris;
  std::map<std::string, Ifcs> ifc_map;
  got_ifcs = get_reg_data(_cfg->_hss, aor_id, associated_uris, ifc_map, trail());

  do
  {
    if (!sdm_access_common(&aor_pair,
                           aor_id,
                           current_sdm,
                           remote_sdms,
                           previous_aor_pair,
                           trail()))
    {
      break;
    }

    std::vector<std::string> binding_ids;

    for (AoR::Bindings::const_iterator i =
           aor_pair->get_current()->bindings().begin();
         i != aor_pair->get_current()->bindings().end();
         ++i)
    {
      // Get a list of the bindings to iterate over
      binding_ids.push_back(i->first);
    }

    for (std::vector<std::string>::const_iterator i = binding_ids.begin();
         i != binding_ids.end();
         ++i)
    {
      std::string b_id = *i;
      AoR::Binding* b = aor_pair->get_current()->get_binding(b_id);

      if (private_id.empty() || private_id == b->_private_id)
      {
        if (!b->_private_id.empty())
        {
          // Record the IMPIs that we need to delete as a result of deleting
          // this binding.
          impis_to_delete.insert(b->_private_id);
        }
        aor_pair->get_current()->remove_binding(b_id);
      }
    }

    aor_pair->get_current()->_associated_uris = associated_uris;
    set_rc = current_sdm->set_aor_data(aor_id,
                                       aor_pair,
                                       trail(),
                                       all_bindings_expired);
    if (set_rc != Store::OK)
    {
      delete aor_pair; aor_pair = NULL;
    }
  }
  while (set_rc == Store::DATA_CONTENTION);

  if (private_id == "")
  {
    // Deregister with any application servers
    TRC_INFO("ID %s", aor_id.c_str());

    if (got_ifcs)
    {
      RegistrationUtils::deregister_with_application_servers(ifc_map[aor_id],
                                                             fifc_service,
                                                             ifc_configuration,
                                                             current_sdm,
                                                             remote_sdms,
                                                             hss,
                                                             aor_id,
                                                             trail());
    }
  }

  return aor_pair;
}

HTTPCode AuthTimeoutTask::timeout_auth_challenge(std::string impu,
                                                 std::string impi,
                                                 std::string nonce)
{
  // Locate the challenge that this timer refers to, to check if the user
  // authenticated against it. If it didn't, we will need to send an
  // AUTHENTICATION_TIMEOUT SAR.
  //
  // Note that we don't bother checking any of the remote IMPI stores if we
  // don't find a record in the local store. This suggests that the IMPI record
  // didn't get replicated to this site but the timer did, which is
  // quite a weird situation to be in. If we do hit it, we'll return a 500
  // response to the timer service which will eventually cause it to retry in a different
  // site, which will hopefully have the data.

  report_sip_all_register_marker(trail(), impu);

  bool success = false;
  ImpiStore::Impi* impi_obj = _cfg->_local_impi_store->get_impi(impi, trail());
  ImpiStore::AuthChallenge* auth_challenge = NULL;
  if (impi_obj != NULL)
  {
    auth_challenge = impi_obj->get_auth_challenge(nonce);
  }
  if (auth_challenge != NULL)
  {
    // Use the original REGISTER's branch parameter for SAS
    // correlation
    correlate_trail_to_challenge(auth_challenge, trail());

    // If authentication completed, we'll have incremented the nonce count.
    // If not, authentication has timed out.
    if (auth_challenge->get_nonce_count() == ImpiStore::AuthChallenge::INITIAL_NONCE_COUNT)
    {
      TRC_DEBUG("AV for %s:%s has timed out", impi.c_str(), nonce.c_str());

      // The AUTHENTICATION_TIMEOUT SAR is idempotent, so there's no
      // problem if the timer pops twice (e.g. if we have high
      // latency and these operations take more than 2 seconds).

      // If either of these operations fail, we return a 500 Internal
      // Server Error - this will trigger the timer service to try a different
      // Sprout, which may have better connectivity to Homestead or Memcached.
      HTTPCode hss_query = _cfg->_hss->update_registration_state(impu, impi, HSSConnection::AUTH_TIMEOUT, auth_challenge->get_scscf_uri(), trail());

      if (hss_query == HTTP_OK)
      {
        success = true;
      }
    }
    else
    {
      SAS::Event event(trail(), SASEvent::AUTHENTICATION_TIMER_POP_IGNORED, 0);
      SAS::report_event(event);

      TRC_DEBUG("Tombstone record indicates Authentication Vector has been used successfully - ignoring timer pop");
      success = true;
    }
  }
  else
  {
    TRC_WARNING("Could not find AV for %s:%s when checking authentication timeout", impi.c_str(), nonce.c_str()); // LCOV_EXCL_LINE
  }
  delete impi_obj;

  return success ? HTTP_OK : HTTP_SERVER_ERROR;
}

//
// APIS for retrieving cached data.
//

void GetCachedDataTask::run()
{
  // This interface is read only so reject any non-GETs.
  if (_req.method() != htp_method_GET)
  {
    send_http_reply(HTTP_BADMETHOD);
    delete this;
    return;
  }

  // Extract the IMPU that has been requested. The URL is of the form
  //
  //   /impu/<public ID>/<element>
  //
  // When <element> is either "bindings" or "subscriptions"
  const std::string prefix = "/impu/";
  std::string full_path = _req.full_path();
  size_t end_of_impu = full_path.find('/', prefix.length());
  std::string impu = full_path.substr(prefix.length(), end_of_impu - prefix.length());
  TRC_DEBUG("Extracted impu %s", impu.c_str());

  // Lookup the IMPU in the store.
  AoRPair* aor_pair = nullptr;
  if (!sdm_access_common(&aor_pair,
                         impu,
                         _cfg->_sdm,
                         _cfg->_remote_sdms,
                         nullptr,
                         trail()))
  {
    send_http_reply(HTTP_SERVER_ERROR);
    delete this;
    return;
  }

  // If there are no bindings we can't have any data data for the requested
  // subscriber (including subscriptions) so return a 404.
  if (aor_pair->get_current()->bindings().empty())
  {
    send_http_reply(HTTP_NOT_FOUND);
    delete aor_pair; aor_pair = NULL;
    delete this;
    return;
  }

  // Now we've got everything we need. Serialize the data that has been
  // requested and return a 200 OK.
  std::string content = serialize_data(aor_pair->get_current());
  _req.add_content(content);
  send_http_reply(HTTP_OK);

  delete aor_pair; aor_pair = NULL;
  delete this;
  return;
}

std::string GetBindingsTask::serialize_data(AoR* aor)
{
  rapidjson::StringBuffer sb;
  rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

  writer.StartObject();
  {
    writer.String(JSON_BINDINGS);
    writer.StartObject();
    {
      for (AoR::Bindings::const_iterator it = aor->bindings().begin();
           it != aor->bindings().end();
           ++it)
      {
        writer.String(it->first.c_str());
        it->second->to_json(writer);
      }
    }
    writer.EndObject();
  }
  writer.EndObject();

  return sb.GetString();
}

std::string GetSubscriptionsTask::serialize_data(AoR* aor)
{
  rapidjson::StringBuffer sb;
  rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

  writer.StartObject();
  {
    writer.String(JSON_SUBSCRIPTIONS);
    writer.StartObject();
    {
      for (AoR::Subscriptions::const_iterator it = aor->subscriptions().begin();
           it != aor->subscriptions().end();
           ++it)
      {
        writer.String(it->first.c_str());
        it->second->to_json(writer);
      }
    }
    writer.EndObject();
  }
  writer.EndObject();

  return sb.GetString();
}

void DeleteImpuTask::run()
{
  TRC_DEBUG("Request to delete an IMPU");

  // This interface only supports DELETEs
  if (_req.method() != htp_method_DELETE)
  {
    send_http_reply(HTTP_BADMETHOD);
    delete this;
    return;
  }

  // Extract the IMPU that has been requested. The URL is of the form
  //
  //   /impu/<public ID>
  const std::string prefix = "/impu/";
  std::string impu = _req.full_path().substr(prefix.length());
  TRC_DEBUG("Extracted impu %s", impu.c_str());

  HTTPCode hss_sc;
  int sc;

  // Expire all the bindings. This will handle deregistering with the HSS and
  // sending NOTIFYs and 3rd party REGISTERs.
  bool all_bindings_expired =
    RegistrationUtils::remove_bindings(_cfg->_sdm,
                                       _cfg->_remote_sdms,
                                       _cfg->_hss,
                                       _cfg->_fifc_service,
                                       _cfg->_ifc_configuration,
                                       impu,
                                       "*",
                                       HSSConnection::DEREG_ADMIN,
                                       trail(),
                                       &hss_sc);

  // Work out what status code to return.
  if (all_bindings_expired)
  {
    // All bindings expired successfully, so the status code is determined by
    // the response from homestead.
    if ((hss_sc >= 200) && (hss_sc < 300))
    {
      // 2xx -> 200.
      sc = HTTP_OK;
    }
    else if (hss_sc == HTTP_NOT_FOUND)
    {
      // 404 -> 404.
      sc = HTTP_NOT_FOUND;
    }
    else if ((hss_sc >= 400) && (hss_sc < 500))
    {
      // Any other 4xx -> 400
      sc = HTTP_BAD_REQUEST;
    }
    else
    {
      // Everything else is mapped to 502 Bad Gateway. This covers 5xx responses
      // (which indicate homestead went wrong) or 3xx responses (which homestead
      // should not return).
      sc = HTTP_BAD_GATEWAY;
    }

    TRC_DEBUG("All bindings expired. Homestead returned %d (-> %d)", hss_sc, sc);
  }
  else
  {
    TRC_DEBUG("Failed to expire bindings");
    sc = HTTP_SERVER_ERROR;
  }
  send_http_reply(sc);

  delete this;
  return;
}

// Will deal with requests sent from Homestead in Push Profile Requests.
// Will send a HTTP return code to Homestead.
void PushProfileTask::run()
{
  // HTTP method must be a PUT
  if (_req.method() != htp_method_PUT)
  {
    TRC_DEBUG("Rejecting request, since HTTP Method isn't PUT");
    send_http_reply(HTTP_BADMETHOD);
    delete this;
    return;
  }

  TRC_DEBUG("Received body %s", (_req.get_rx_body()).c_str());
  HTTPCode rc = parse_request(_req.get_rx_body(), trail());

  if (rc != HTTP_OK)
  {
    TRC_WARNING("Request body is invalid, send %d", rc);
    send_http_reply(rc);
    delete this;
    return;
  }

  rc = update_store_to_send_any_notifys(trail());

  if (rc != HTTP_OK)
  {
    TRC_DEBUG("Failure to handle request, send %d", rc);
    send_http_reply(rc);
    delete this;
    return;
  }
  else
  {
    TRC_DEBUG("Successful, sending %d", rc);
  }
  send_http_reply(rc);
  delete this;
}

HTTPCode PushProfileTask::parse_request(std::string body, SAS::TrailId trail)
{
  std::string user_data_xml;
  rapidjson::Document doc;
  doc.Parse<0>(body.c_str());

  if (doc.HasParseError())
  {
    TRC_INFO("Failed to parse data as JSON: %s\nError: %s",
             body.c_str(),
             rapidjson::GetParseError_En(doc.GetParseError()));
    return HTTP_BAD_REQUEST;
  }

  try
  {
    JSON_GET_STRING_MEMBER(doc, "user-data-xml", user_data_xml);
  }
  catch (JsonFormatError err)
  {
    TRC_WARNING("User data not available in the JSON");
    return HTTP_BAD_REQUEST;
  }

  const std::string prefix = "/registrations/";
  std::string full_path = _req.full_path();
  size_t end_of_impu = full_path.length();
  _default_public_id = full_path.substr(prefix.length(), end_of_impu - prefix.length());
  TRC_DEBUG("Extracted impu %s", _default_public_id.c_str());

  rapidxml::xml_document<>* root = new rapidxml::xml_document<>;

  try
  {
    root->parse<0>(root->allocate_string(user_data_xml.c_str()));
  }
  catch (rapidxml::parse_error& err)
  {
    // report to the user the failure and their locations in the document.
    TRC_WARNING("Failed to parse XML:\n %s\n %s", body.c_str(), err.what());
    delete root;
    root = NULL;
    return HTTP_BAD_REQUEST;
  }

  rapidxml::xml_node<>* imss = root->first_node(RegDataXMLUtils::IMS_SUBSCRIPTION);

  // Decode service profile from the XML. Create and populate an instance of the
  // Associated URIs class
  if (SproutXmlUtils::get_uris_from_service_profile(imss,
                                                     _associated_uris,
                                                     trail))
  {
    delete root; root = NULL;
    return HTTP_OK;
  }
  else
  {
    delete root; root = NULL;
    return HTTP_BAD_REQUEST;
  }
}

HTTPCode PushProfileTask::update_store_to_send_any_notifys(SAS::TrailId trail)
{
  AoRPair* aor_pair = NULL;

  if(!sdm_access_common(&aor_pair,
                         _default_public_id,
                         _cfg->_sdm,
                         _cfg->_remote_sdms,
                         NULL,
                         trail))
  {
    TRC_DEBUG("Could not get AoR data from SDM");
    return HTTP_SERVER_ERROR;
  }

  TRC_DEBUG("Obtained AoR data");

  bool all_bindings_expired = false;
  Store::Status set_rc;
  aor_pair->get_current()->_associated_uris = _associated_uris;
  set_rc = _cfg->_sdm->set_aor_data(_default_public_id,
                                    aor_pair,
                                    trail,
                                    all_bindings_expired);
  if (set_rc != Store::OK)
  {
    TRC_DEBUG("Could not set AoR data to SDM");
    return HTTP_SERVER_ERROR;
  }

  // If we have any remote stores, try to store this in them too.  We don't worry
  // about failures in this case.
  // LCOV_EXCL_START
  if (aor_pair != NULL)
  {
    for (std::vector<SubscriberDataManager*>::const_iterator sdm = _cfg->_remote_sdms.begin();
         sdm != _cfg->_remote_sdms.end();
	 ++sdm)
    {
      if ((*sdm)->has_servers())
      {
        (*sdm)->set_aor_data(_default_public_id,
                              aor_pair,
                              trail,
                              all_bindings_expired);
      }
    }
  }
  // LCOV_EXCL_STOP

  if (all_bindings_expired)
  {
    TRC_DEBUG("All bindings have expired - triggering deregistration at the HSS");
    SAS::Event event(trail, SASEvent::REGISTRATION_EXPIRED, 0);
    event.add_var_param(_default_public_id);
    SAS::report_event(event);

    // Get the S-CSCF URI off the AoR to put on the SAR.
    AoR* aor = aor_pair->get_current();

    _cfg->_hss->update_registration_state(_default_public_id, "", HSSConnection::DEREG_TIMEOUT, aor->_scscf_uri, trail);
  }

  delete aor_pair; aor_pair = NULL;
  return HTTP_OK;
}
