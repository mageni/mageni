###############################################################################
# OpenVAS Vulnerability Test
#
# OS Detection Consolidation and Reporting
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105937");
  script_version("2019-05-22T11:40:52+0000");
  script_tag(name:"last_modification", value:"2019-05-22 11:40:52 +0000 (Wed, 22 May 2019)");
  script_tag(name:"creation_date", value:"2016-02-19 11:19:54 +0100 (Fri, 19 Feb 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("OS Detection Consolidation and Reporting");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  # Keep order the same as in host_details.inc. Also add NVTs registering an OS there if adding here.
  # nmap_net.nasl was not added as this is in ACT_SCANNER and doesn't use register_and_report_os yet
  # Keep in sync with os_fingerprint.nasl as well.
  script_dependencies("gb_greenbone_os_detect.nasl", "gb_ami_megarac_sp_web_detect.nasl",
                      "gb_ros_detect.nasl", "gb_apple_mobile_detect.nasl",
                      "gb_vmware_esx_web_detect.nasl", "gb_vmware_esx_snmp_detect.nasl",
                      "gb_ssh_cisco_ios_get_version.nasl", "gb_cisco_cucmim_version.nasl",
                      "gb_cisco_cucm_version.nasl", "gb_cisco_nx_os_version.nasl",
                      "gb_cyclades_detect.nasl", "gb_fortios_detect.nasl",
                      "gb_cisco_esa_version.nasl", "gb_cisco_wsa_version.nasl",
                      "gb_cisco_csma_version.nasl", "gb_cisco_ip_phone_detect.nasl",
                      "gb_cisco_ios_xr_version.nasl", "gb_ssh_junos_get_version.nasl",
                      "gb_palo_alto_panOS_version.nasl", "gb_screenos_version.nasl",
                      "gb_extremeos_snmp_detect.nasl", "gb_tippingpoint_sms_consolidation.nasl",
                      "gb_cisco_asa_version_snmp.nasl", "gb_cisco_asa_version.nasl",
                      "gb_cisco_asa_detect.nasl",
                      "gb_arista_eos_snmp_detect.nasl", "gb_netgear_prosafe_consolidation.nasl",
                      "gb_hirschmann_consolidation.nasl", "gb_mikrotik_router_routeros_consolidation.nasl",
                      "gb_xenserver_version.nasl", "gb_cisco_ios_xe_version.nasl",
                      "gb_mcafee_email_gateway_version.nasl", "gb_brocade_netiron_snmp_detect.nasl",
                      "gb_brocade_fabricos_consolidation.nasl",
                      "gb_arubaos_detect.nasl", "gb_cyberoam_umt_ngfw_detect.nasl",
                      "gb_aerohive_hiveos_detect.nasl", "gb_qnap_nas_detect.nasl",
                      "gb_synology_dsm_detect.nasl", "gb_drobo_nas_consolidation.nasl",
                      "gb_euleros_snmp_detect.nasl", "gb_simatic_s7_version.nasl",
                      "gb_simatic_cp_consolidation.nasl", "gb_simatic_scalance_snmp_detect.nasl",
                      "gb_siemens_ruggedcom_consolidation.nasl", "ilo_detect.nasl",
                      "gb_watchguard_fireware_detect.nasl", "gb_vibnode_consolidation.nasl",
                      "gb_hyperip_consolidation.nasl", "gb_avm_fritz_box_detect.nasl",
                      "gb_dlink_dap_detect.nasl", "gb_dlink_dsl_detect.nasl",
                      "gb_dlink_dns_detect.nasl", "gb_dlink_dir_detect.nasl",
                      "gb_dlink_dwr_detect.nasl", "gb_wd_mycloud_consolidation.nasl",
                      "gb_intelbras_ncloud_devices_http_detect.nasl", "gb_netapp_data_ontap_consolidation.nasl",
                      "gb_ricoh_iwb_detect.nasl", "gb_codesys_os_detection.nasl",
                      "gb_simatic_hmi_consolidation.nasl", "gb_wago_plc_consolidation.nasl",
                      "gb_rockwell_micrologix_consolidation.nasl", "gb_rockwell_powermonitor_http_detect.nasl",
                      "gb_beward_ip_cameras_detect_consolidation.nasl", "gb_zavio_ip_cameras_detect.nasl",
                      "gb_tp_link_ip_cameras_detect.nasl", "gb_pearl_ip_cameras_detect.nasl",
                      "gb_riverbed_steelcentral_version.nasl", "gb_riverbed_steelhead_ssh_detect.nasl",
                      "gb_riverbed_steelhead_http_detect.nasl", "gb_windows_cpe_detect.nasl",
                      "gather-package-list.nasl", "gb_cisco_pis_version.nasl",
                      "gb_checkpoint_fw_version.nasl", "gb_smb_windows_detect.nasl",
                      "gb_nec_communication_platforms_detect.nasl", "gb_ssh_os_detection.nasl",
                      "gb_citrix_netscaler_version.nasl",
                      "gb_junos_snmp_version.nasl", "gb_snmp_os_detection.nasl",
                      "gb_dns_os_detection.nasl", "gb_ftp_os_detection.nasl",
                      "smb_nativelanman.nasl", "gb_ucs_detect.nasl",
                      "sw_http_os_detection.nasl", "sw_mail_os_detection.nasl",
                      "sw_telnet_os_detection.nasl", "gb_mysql_mariadb_os_detection.nasl",
                      "apcnisd_detect.nasl",
                      "ntp_open.nasl", "remote-detect-MDNS.nasl",
                      "mssqlserver_detect.nasl", "gb_apple_tv_version.nasl",
                      "gb_apple_tv_detect.nasl", "gb_upnp_os_detection.nasl",
                      "gb_sip_os_detection.nasl", "gb_check_mk_agent_detect.nasl",
                      "ms_rdp_detect.nasl", "gb_apache_activemq_detect.nasl",
                      "dcetest.nasl", "gb_hnap_os_detection.nasl",
                      "gb_ident_os_detection.nasl", "gb_pihole_detect.nasl",
                      "gb_dropbear_ssh_detect.nasl", "gb_rtsp_os_detection.nasl",
                      "gb_nntp_os_detection.nasl", "gb_android_adb_detect.nasl",
                      "netbios_name_get.nasl",
                      "gb_nmap_os_detection.nasl", "os_fingerprint.nasl");

  script_xref(name:"URL", value:"https://www.mageni.net");

  script_tag(name:"summary", value:"This script consolidates the OS information detected by several NVTs and tries to find the best matching OS.

  Furthermore it reports all previously collected information leading to this best matching OS. It also reports possible additional information
  which might help to improve the OS detection.

  If any of this information is wrong or could be improved please consider to it.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");

found_best = FALSE;
found_os = ""; # nb: To make openvas-nasl-lint happy...

# nb: We only want to check the CPE entries
foreach oid( OS_CPE_SRC ) {
  os = get_kb_list( "HostDetails/NVT/" + oid + "/OS" );
  if( ! isnull( os ) ) {
    res =  make_list( os );
    foreach entry( res ) {
      # Discard non CPE entries
      if( "cpe:/" >!< entry )
        continue;

      desc = get_kb_item( "HostDetails/NVT/" + oid );

      if( ! found_best ) {

        os_reports = get_kb_list( "os_detection_report/reports/" + oid + "/*" );
        if( ! os_reports ) continue;

        # Use keys to be able to extract the port and proto later
        foreach key( keys( os_reports ) ) {

          # We need the port and proto for the host_runs kb entry later
          tmp   = split( key, sep:"/", keep:FALSE );
          port  = tmp[3];
          proto = tmp[4];

          # There might be multiple keys/entries for the same port (e.g. http)
          # so using get_kb_list instead() of get_kb_item() here.
          os_reports = get_kb_list( key );
          foreach os_report( os_reports ) {
            if( ! found_best ) {
              report = 'Best matching OS: ' + os_report + '\n';
              found_best = TRUE;
              best_match = entry;
              best_match_oid = oid;
              best_match_desc = desc;
              best_match_report = os_report; # To avoid that it will be added to the "Other OS detections" text (see the checks down below)

              host_runs_list = get_kb_list( "os_detection_report/host_runs/" + oid + "/" + port + "/" + proto );

              # We could have multiple host_runs entries on the same port (e.g. http)
              # Choose the first match here
              foreach host_runs( host_runs_list ) {
                if( host_runs == "unixoide" ) {
                  set_key = "Host/runs_unixoide";
                } else if( host_runs == "windows" ) {
                  set_key = "Host/runs_windows";
                } else {
                  # This makes sure that we still scheduling NVTs using Host/runs_unixoide as a fallback
                  set_key = "Host/runs_unixoide";
                }
                if( ! get_kb_item( set_key ) ) {
                  set_kb_item( name:set_key, value:TRUE );
                }
              }
            } else {
              if( os_report >!< found_os && os_report >!< best_match_report )
               set_key = os_report;
            }
          }
        }
      } else {
        os_reports = get_kb_list( "os_detection_report/reports/" + oid + "/*" );
        foreach os_report( os_reports ) {
          if( os_report >!< found_os && os_report >!< best_match_report )
           set_key = os_report;
        }
      }
    }
  }
}

if( ! found_best ) {
  report += "No Best matching OS identified. Please see the NVT 'Unknown OS and Service Banner Reporting' (OID: 1.3.6.1.4.1.25623.1.0.108441) ";
  report += "for possible ways to identify this OS.";
  # nb: Setting the runs_key to unixoide makes sure that we still schedule NVTs using Host/runs_unixoide as a fallback
  set_kb_item( name:"Host/runs_unixoide", value:TRUE );
} else {
  # TBD: Move into host_details.nasl?
  set_kb_item( name:"HostDetails/OS/BestMatch", value:best_match );
  set_kb_item( name:"HostDetails/OS/BestMatch/Details", value:best_match_oid + ';' + best_match_desc );

  # Store link between os_detection.nasl and gb_os_eol.nasl
  # nb: We don't use the host_details.inc functions in both so we need to call this directly.
  register_host_detail( name:"OS-Detection", value:best_match );
  register_host_detail( name:best_match, value:"general/tcp" ); # the port:0 from below
  register_host_detail( name:"port", value:"general/tcp" ); # the port:0 from below
}

if( found_os )
 set_key = found_os;

log_message( port:0, data:report );

exit( 0 );
