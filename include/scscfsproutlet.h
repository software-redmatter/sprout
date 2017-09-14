/**
 * @file scscfsproutlet.cpp Definition of the S-CSCF Sproutlet classes,
 *                          implementing S-CSCF specific SIP proxy functions.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

// TODO - Finish defining this file, and the ones on which it depends
// TODO - Should we split this into SCSCFSproutlet and SCSCFProxyProvider?

#ifndef SCSCFSPROUTLET_H__
#define SCSCFSPROUTLET_H__

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <stdint.h>
}

#include <vector>
#include <unordered_map>

#include "pjutils.h"
#include "enumservice.h"
#include "analyticslogger.h"
#include "subscriber_data_manager.h"
#include "stack.h"
#include "sessioncase.h"
#include "ifchandler.h"
#include "mmfservice.h"
#include "hssconnection.h"
#include "aschain.h"
#include "acr.h"
#include "sproutlet.h"
#include "snmp_counter_table.h"
#include "session_expires_helper.h"
#include "as_communication_tracker.h"

class SCSCFSproutlet : public Sproutlet
{
public:
  static const int DEFAULT_SESSION_CONTINUED_TIMEOUT = 2000;
  static const int DEFAULT_SESSION_TERMINATED_TIMEOUT = 4000;

  SCSCFSproutlet(const std::string& name,
                 const std::string& scscf_name,
                 const std::string& scscf_cluster_uri,
                 const std::string& scscf_node_uri,
                 const std::string& icscf_uri,
                 const std::string& bgcf_uri,
                 const std::string& mmf_cluster_uri,
                 const std::string& mmf_node_uri,
                 int port,
                 const std::string& uri,
                 SubscriberDataManager* sdm,
                 std::vector<SubscriberDataManager*> remote_sdms,
                 HSSConnection* hss,
                 EnumService* enum_service,
                 ACRFactory* acr_factory,
                 SNMP::SuccessFailCountByRequestTypeTable* incoming_sip_transactions_tbl,
                 SNMP::SuccessFailCountByRequestTypeTable* outgoing_sip_transactions_tbl,
                 bool override_npdi,
                 MMFService* mmfservice,
                 FIFCService* fifcservice,
                 IFCConfiguration ifc_configuration,
                 int session_continued_timeout = DEFAULT_SESSION_CONTINUED_TIMEOUT,
                 int session_terminated_timeout = DEFAULT_SESSION_TERMINATED_TIMEOUT,
                 AuthenticationProvider* authentication_provider,
                 RegistrarProvider* registrar_provider,
                 SubscriptionProvider* subscription_provider,
                 AsCommunicationTracker* sess_term_as_tracker = NULL,
                 AsCommunicationTracker* sess_cont_as_tracker = NULL);
  ~SCSCFSproutlet();

  bool init();

  // TODO - Needs to return either RegistrarTsx, SubscriptionTsx or
  // SCSCFProxyTsx, depending on context.
  SproutletTsx* get_tsx(SproutletHelper* helper,
                        const std::string& alias,
                        pjsip_msg* req,
                        pjsip_sip_uri*& next_hop,
                        pj_pool_t* pool,
                        SAS::TrailId trail);

  // Methods used to change the values of internal configuration during unit
  // test.
  void set_override_npdi(bool v) { _override_npdi = v; }
  void set_session_continued_timeout(int timeout) { _session_continued_timeout_ms = timeout; }
  void set_session_terminated_timeout(int timeout) { _session_terminated_timeout_ms = timeout; }

  inline bool should_override_npdi() const
  {
    return _override_npdi;
  }

private:

  /// Returns the AS chain table for this system.
  AsChainTable* as_chain_table() const;

  /// Returns the service name of the entire S-CSCF.
  const std::string scscf_service_name() const;

  /// Returns the configured S-CSCF cluster URI for this system.
  const pjsip_uri* scscf_cluster_uri() const;

  /// Returns the configured S-CSCF node URI for this system.
  const pjsip_uri* scscf_node_uri() const;

  /// Returns the configured I-CSCF URI for this system.
  const pjsip_uri* icscf_uri() const;

  /// Returns the configured BGCF URI for this system.
  const pjsip_uri* bgcf_uri() const;

  /// Returns the configured MMF cluster URI for this system.
  const pjsip_uri* mmf_cluster_uri() const;

  /// Returns the configured MMF node URI for this system.
  const pjsip_uri* mmf_node_uri() const;

  MMFService* mmfservice() const;
  FIFCService* fifcservice() const;
  IFCConfiguration ifc_configuration() const;

  /// Gets all bindings for the specified Address of Record from the local or
  /// remote registration stores.
  void get_bindings(const std::string& aor,
                    AoRPair** aor_pair,
                    SAS::TrailId trail);

  /// Removes the specified binding for the specified Address of Record from
  /// the local or remote registration stores.
  void remove_binding(const std::string& aor,
                      const std::string& binding_id,
                      SAS::TrailId trail);

  /// Read data for a public user identity from the HSS. Returns the HTTP result
  /// code obtained from homestead.
  long read_hss_data(const std::string& public_id,
                     const std::string& private_id,
                     const std::string& req_type,
                     const std::string& scscf_uri,
                     bool cache_allowed,
                     bool& registered,
                     bool& barred,
                     std::string& default_uri,
                     std::vector<std::string>& uris,
                     std::vector<std::string>& aliases,
                     Ifcs& ifcs,
                     std::deque<std::string>& ccfs,
                     std::deque<std::string>& ecfs,
                     const std::string& wildcard,
                     SAS::TrailId trail);

  /// Record that communication with an AS failed.
  ///
  /// @param uri               - The URI of the AS.
  /// @param reason            - Textual representation of the reason the AS is
  ///                            being treated as failed.
  /// @param default_handling  - The AS's default handling.
  void track_app_serv_comm_failure(const std::string& uri,
                                   const std::string& reason,
                                   DefaultHandling default_handling);

  /// Record that communication with an AS succeeded.
  ///
  /// @param uri               - The URI of the AS.
  /// @param default_handling  - The AS's default handling.
  void track_app_serv_comm_success(const std::string& uri,
                                   DefaultHandling default_handling);

  /// Record the time an INVITE took to reach ringing state.
  ///
  /// @param ringing_us Time spent until a 180 Ringing, in microseconds.
  void track_session_setup_time(uint64_t tsx_start_time_usec, bool video_call);

  /// Translate RequestURI using ENUM service if appropriate.
  void translate_request_uri(pjsip_msg* req, pj_pool_t* pool, SAS::TrailId trail);

  /// Get an ACR instance from the factory.
  /// @param trail                SAS trail identifier to use for the ACR.
  /// @param initiator            The initiator of the SIP transaction (calling
  ///                             or called party).
  ACR* get_acr(SAS::TrailId trail, ACR::Initiator initiator, ACR::NodeRole role);

  /// The service name of the entire S-CSCF.
  std::string _scscf_name;

  /// A URI which routes to the S-CSCF cluster.
  pjsip_uri* _scscf_cluster_uri;

  /// A URI which routes to this particular S-CSCF node.  This must be
  /// constructed using an IP address or a domain name which resolves to this
  /// Sprout node only.
  pjsip_uri* _scscf_node_uri;

  /// A URI which routes to the URI cluster.
  pjsip_uri* _icscf_uri;

  /// A URI which routes to the BGCF.
  pjsip_uri* _bgcf_uri;

  /// A URI which routes to the MMF cluster.
  pjsip_uri* _mmf_cluster_uri;

  /// A URI which routes to this particular MMF node.  This must be
  /// constructed using an IP address or a domain name which resolves to this
  /// Sprout node only.
  pjsip_uri* _mmf_node_uri;

  SubscriberDataManager* _sdm;
  std::vector<SubscriberDataManager*> _remote_sdms;

  HSSConnection* _hss;

  EnumService* _enum_service;

  ACRFactory* _acr_factory;

  AsChainTable* _as_chain_table;

  bool _override_npdi;
  MMFService* _mmfservice;
  FIFCService* _fifcservice;
  IFCConfiguration _ifc_configuration;

  /// Timeouts related to default handling of unresponsive application servers.
  int _session_continued_timeout_ms;
  int _session_terminated_timeout_ms;

  /// String versions of the cluster URIs
  std::string _scscf_cluster_uri_str;
  std::string _scscf_node_uri_str;
  std::string _icscf_uri_str;
  std::string _bgcf_uri_str;
  std::string _mmf_cluster_uri_str;
  std::string _mmf_node_uri_str;

  SNMP::CounterTable* _routed_by_preloaded_route_tbl = NULL;
  SNMP::CounterTable* _invites_cancelled_before_1xx_tbl = NULL;
  SNMP::CounterTable* _invites_cancelled_after_1xx_tbl = NULL;
  SNMP::EventAccumulatorTable* _video_session_setup_time_tbl = NULL;
  SNMP::EventAccumulatorTable* _audio_session_setup_time_tbl = NULL;
  SNMP::CounterTable* _forked_invite_tbl = NULL;
  SNMP::CounterTable* _barred_calls_tbl = NULL;


  AuthenticationProvider* _authentication_provider;
  RegistrarProvider* _registrar_provider;
  SubscriptionProvider* _subscription_provider;

  AsCommunicationTracker* _sess_term_as_tracker;
  AsCommunicationTracker* _sess_cont_as_tracker;
};

#endif
