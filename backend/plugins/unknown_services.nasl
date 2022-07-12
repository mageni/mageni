###############################################################################
# OpenVAS Vulnerability Test
#
# Collect banner of unknown services
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11154");
  script_version("2019-05-09T07:03:38+0000");
  script_tag(name:"last_modification", value:"2019-05-09 07:03:38 +0000 (Thu, 09 May 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Collect banner of unknown services");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 Michel Arboi");
  script_family("Service detection");
  # IMPORTANT: Don't add telnet.nasl or os_detection.nasl in here which have (indirect-)
  # dependencies to this NVT. Adding this dependency would cause a dependency cycle...
  script_dependencies("alcatel_backdoor_switch.nasl", "apache_SSL_complain.nasl",
                      "apcnisd_detect.nasl", "asip-status.nasl",
                      "auth_enabled.nasl", "BigAnt_detect.nasl",
                      "bugbear.nasl", "check_dns_tcp.nasl",
                      "cheopsNG_detect.nasl", "cifs445.nasl",
                      "distcc_detection.nasl", "dns_server_tcp.nasl",
                      "dont_print_on_printers.nasl", "echo.nasl",
                      "ePo_detect.nasl", "external_svc_ident.nasl",
                      "famd_detect.nasl", "find_service6.nasl",
                      "gb_ab_ethernet_detect.nasl", "gb_aerospike_telnet_detect.nasl",
                      "gb_aerospike_xdr_detect.nasl", "gb_amqp_detect.nasl",
                      "gb_android_adb_detect.nasl", "gb_apache_cassandra_detect.nasl",
                      "gb_apache_derby_detect.nasl", "gb_apache_jserv_detect.nasl",
                      "gb_arkeia_virtual_appliance_detect_617.nasl", "gb_backupexec_detect.nasl",
                      "gb_check_mk_agent_detect.nasl", "gb_codesys_detect.nasl", "gb_crestron_cip_detect.nasl",
                      "gb_dnp3_detect.nasl", "gb_dont_scan_fragile_device.nasl",
                      "gb_emc_networker_detect.nasl", "gb_ethernetip_detect.nasl",
                      "gb_fins_tcp_detect.nasl", "gb_hid_vertx_discoveryd_detect.nasl",
                      "gb_ibm_soliddb_detect.nasl", "gb_ibm_websphere_mq_mqi_detect.nasl",
                      "gb_informix_detect.nasl", "gb_kerberos_detect.nasl",
                      "gb_lantronix_mgm_tcp_detect.nasl", "gb_logitech_media_server_tcp_detect.nasl",
                      "gb_memcachedb_detect.nasl",
                      "gb_memcached_detect.nasl", "gb_modbus_detect.nasl",
                      "gb_mongodb_detect.nasl", "gb_mqtt_detect.nasl",
                      "gb_netware_core_protocol_detect.nasl", "gb_niagara_fox_detect.nasl",
                      "gb_opc_ua_detect.nasl", "gb_openvas_administrator_detect.nasl",
                      "gb_openvas_manager_detect.nasl", "gb_openvpn_detect.nasl",
                      "gb_ossec-authd_detect.nasl",
                      "gb_pcworx_detect.nasl", "gb_proconos_detect.nasl",
                      "gb_redis_detect.nasl", "gb_riak_detect.nasl",
                      "gb_rmi_registry_detect.nasl", "gb_sap_maxdb_detect.nasl",
                      "gb_sap_router_detect.nasl", "gb_sap_msg_service_detect.nasl",
                      "gb_sap_diag_service_detect.nasl", "gb_simatic_s7_cotp_detect.nasl",
                      "gb_sybase_tcp_listen_detect.nasl", "gb_symantec_pcanywhere_access_server_detect.nasl",
                      "gb_teamspeak_detect.nasl", "gb_teamspeak_udp_detect.nasl",
                      "gb_winrm_detect.nasl", "gnutella_detect.nasl",
                      "hp_data_protector_installed.nasl", "ircd.nasl",
                      "ingres_db_detect.nasl",
                      "kerio_firewall_admin_port.nasl", "landesk_detect.nasl",
                      "lcdproc_detect.nasl", "ldap_detect.nasl",
                      "ms_rdp_detect.nasl", "mssqlserver_detect.nasl",
                      "mysql_version.nasl", "nagios_statd_detect.nasl",
                      "nessus_detect.nasl", "nntpserver_detect.nasl",
                      "ntp_open.nasl", "oracle_tnslsnr_version.nasl",
                      "ossim_server_detect.nasl", "PC_anywhere_tcp.nasl",
                      "perforce_detect.nasl", "pjl_detect.nasl",
                      "postgresql_detect.nasl",
                      "pptp_detect.nasl", "qmtp_detect.nasl",
                      "radmin_detect.nasl", "remote-detect-filemaker.nasl",
                      "remote-detect-firebird.nasl", "rpcinfo.nasl",
                      "rsh.nasl", "rtsp_detect.nasl",
                      "secpod_rpc_portmap_tcp.nasl", "SHN_discard.nasl",
                      "sip_detection_tcp.nasl", "socks.nasl",
                      "ssh_detect.nasl", "sw_jenkins_detect.nasl",
                      "sw_netstat_service_detect.nasl", "sw_obby_detect.nasl",
                      "sw_policyd-weight_detect.nasl", "sw_sphinxsearch_detect.nasl",
                      "telnet.nasl",
                      "vmware_server_detect.nasl", "vnc.nasl",
                      "vnc_security_types.nasl", "xmpp_detect.nasl",
                      "X.nasl", "xtel_detect.nasl",
                      "xtelw_detect.nasl", "yahoo_msg_running.nasl",
                      "zabbix_detect.nasl");

  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_sap_gateway_detect.nasl");

  script_require_ports("Services/unknown");

  script_tag(name:"summary", value:"This plugin collect the banner from unknown/unidentified services.

  The actual reporting takes place in the separate NVT 'Unknown OS and Service Banner Reporting'
  OID: 1.3.6.1.4.1.25623.1.0.108441.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("dump.inc");

function unknown_banner_report( port ) {

  local_var banner, method, port;

  if( ! port )
    return;

  foreach method( make_list( "spontaneous", "get_httpHex", "get_http", "helpHex", "help", "xmlHex", "xml", "jsonHex", "json", "sipHex", "sip", "binHex", "bin" ) ) {
    banner = get_kb_item( "FindService/tcp/" + port + "/" + method );
    # Later evaluated methods in the foreach loop might have
    # more data so only return here when having enough data.
    if( banner && strlen( banner ) >= 3 ) {
      return( make_list( method, banner ) );
    }
  }

  # nb: Those are coming from / are set by nasl_builtin_find_service.c
  banner = get_kb_item( "unknown/banner/" + port );
  if( banner )
    return( make_list( "'unknown/banner/' KB entry", banner ) );

  banner = get_kb_item( "Banner/" + port );
  if( banner )
    return( make_list( "'Banner/' KB entry", banner ) );
}

port = get_kb_item( "Services/unknown" );
if( ! port )
  exit( 0 );

if( ! get_port_state( port ) )
  exit( 0 );

if( port == 139 )
  exit( 0 ); # Avoid silly messages

if( ! service_is_unknown( port:port ) )
  exit( 0 );

banner = unknown_banner_report( port:port );
if( ! banner )
  exit( 0 );

if( strlen( banner[1] ) >= 3 ) {

  set_kb_item( name:"unknown_os_or_service/available", value:TRUE ); # Used in gb_unknown_os_service_reporting.nasl

  if( "Hex" >< banner[0] ) {
    hexbanner = hexdump( ddata:hex2raw( s:banner[1] ) );
  } else {
    hexbanner = hexdump( ddata:banner[1] );
  }

  report = 'Method: ' + banner[0] + '\n\n' + hexbanner;
  set_kb_item( name:"unknown_service_report/unknown_banner/" + port + "/report", value:report );
}

exit( 0 );
