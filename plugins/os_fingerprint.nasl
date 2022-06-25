###################################################################
# OpenVAS Vulnerability Test
#
# ICMP based OS Fingerprinting
#
# LSS-NVT-2009-002
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2009 LSS <http://www.lss.hr>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
###################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102002");
  script_version("2019-05-22T11:40:52+0000");
  script_tag(name:"last_modification", value:"2019-05-22 11:40:52 +0000 (Wed, 22 May 2019)");
  script_tag(name:"creation_date", value:"2009-05-19 12:05:50 +0200 (Tue, 19 May 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("ICMP based OS Fingerprinting");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 LSS");
  script_family("Product detection");
  # Keep order the same as in host_details.inc. Also add NVTs registering an OS there if adding here.
  # nmap_net.nasl was not added as this is in ACT_SCANNER and doesn't use register_and_report_os yet
  # Keep in sync with os_detection.nasl but without gb_nmap_os_detection.nasl and the own os_fingerprint.nasl
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
                      "netbios_name_get.nasl", "global_settings.nasl");
  script_exclude_keys("keys/TARGET_IS_IPV6");

  script_xref(name:"URL", value:"http://www.phrack.org/issues.html?issue=57&id=7#article");

  script_tag(name:"summary", value:"This script performs ICMP based OS fingerprinting (as described by
  Ofir Arkin and Fyodor Yarochkin in Phrack #57). It can be used to determine
  remote operating system version. The result is stored in the KB for later analysis only.");

  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

if( TARGET_IS_IPV6() ) exit( 0 );

# nb: We only want to run this NVT as a "last fallback" if all of the other
# more reliable OS detections failed. This NVT isn't that reliable these days
# and takes around 10 seconds (or even more) for each host to finish.
reports = get_kb_list( "os_detection_report/reports/*" );
if( reports && max_index( keys( reports ) ) > 0 ) {
  exit( 0 );
}

ATTEMPTS = 2;
passed = 0;

include("host_details.inc");

SCRIPT_DESC = "ICMP based OS Fingerprinting";

# Fingerprints extracted from xprobe2.conf
# -----
# The fingerprints table is divided into sections. Each section starts with its
# label, followed by the corresponding fingerprints. An empty string closes the
# section.
# In case there are several matches for the remote OS, then the section title(s)
# will be displayed instead of the whole list of matches.

FINGERPRINTS = make_list(
    "AIX,cpe:/o:ibm:aix",
        "AIX 5.1,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,y,!0,<255,y,0,1,!0,8,<255,0,BAD,OK,>20,OK",
        "AIX 4.3.3,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,y,!0,<255,y,0,1,!0,8,<255,0,BAD,OK,>20,OK",
    "",
    "Apple Mac OS X,cpe:/o:apple:mac_os_x",
        "Apple Mac OS X 10.2.0,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.2.1,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.2.2,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.2.3,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.2.4,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.2.5,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.2.6,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.2.7,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.2.8,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.3.0,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.3.1,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.3.2,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.3.3,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.3.4,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.3.5,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.3.6,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.3.7,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.3.8,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.3.9,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.4.0,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.4.1,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
    "",
    "Cisco IOS,cpe:/o:cisco:ios",
        "Cisco IOS 12.3,y,!0,SENT,!0,1,<255,y,SENT,<255,n,SENT,<255,y,SENT,<255,y,0xc0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "Cisco IOS 12.2,y,!0,SENT,!0,1,<255,y,SENT,<255,n,SENT,<255,y,SENT,<255,y,0xc0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "Cisco IOS 12.0,y,!0,SENT,!0,1,<255,y,SENT,<255,n,SENT,<255,y,SENT,<255,y,0xc0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "Cisco IOS 11.3,y,!0,SENT,!0,1,<255,y,SENT,<255,n,SENT,<255,y,SENT,<255,y,0xc0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "Cisco IOS 11.2,y,!0,SENT,!0,1,<255,y,SENT,<255,n,SENT,<255,y,SENT,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "Cisco IOS 11.1,y,!0,SENT,!0,1,<255,y,SENT,<255,n,SENT,<255,y,SENT,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
    "",
    "FreeBSD,cpe:/o:freebsd:freebsd",
        "FreeBSD 5.4,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 5.3,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 5.2.1,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 5.2,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 5.1,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 5.0,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 4.11,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 4.10,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 4.9,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 4.8,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 4.7,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 4.6.2,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 4.6,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 4.5,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 4.4,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 4.3,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,OK,OK,OK,OK",
        "FreeBSD 4.2,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,OK,OK,OK,OK",
        "FreeBSD 4.1.1,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,OK,OK,OK,OK",
        "FreeBSD 4.0,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,BAD,FLIPPED,OK,FLIPPED",
        "FreeBSD 3.5.1,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,BAD,FLIPPED,OK,FLIPPED",
        "FreeBSD 3.4,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,BAD,FLIPPED,OK,FLIPPED",
        "FreeBSD 3.3,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,BAD,FLIPPED,OK,FLIPPED",
        "FreeBSD 3.2,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,BAD,FLIPPED,OK,FLIPPED",
        "FreeBSD 3.1,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,BAD,FLIPPED,OK,FLIPPED",
        "FreeBSD 2.2.8,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,BAD,FLIPPED,OK,FLIPPED",
        "FreeBSD 2.2.7,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,BAD,FLIPPED,OK,FLIPPED",
    "",
    "HP UX,cpe:/o:hp:hp-ux",
        "HP UX 11.0x,y,!0,!0,!0,1,<255,n,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,64,<255,OK,OK,OK,OK,OK",
        "HP UX 11.0,y,!0,!0,!0,1,<255,n,!0,<255,y,!0,<255,n,!0,<255,y,0,1,!0,64,<255,OK,OK,OK,OK,OK",
    "",
    "HP JetDirect,cpe:/h:hp:jetdirect",
        "HP JetDirect ROM A.03.17 EEPROM A.04.09,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,0,OK,OK,OK",
        "HP JetDirect ROM A.05.03 EEPROM A.05.05,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,0,OK,OK,OK",
        "HP JetDirect ROM F.08.01 EEPROM F.08.05,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM F.08.08 EEPROM F.08.05,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM F.08.08 EEPROM F.08.20,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM G.05.34 EEPROM G.05.35,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,0,OK,OK,OK",
        "HP JetDirect ROM G.06.00 EEPROM G.06.00,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM G.07.02 EEPROM G.07.17,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM G.07.02 EEPROM G.07.20,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM G.07.02 EEPROM G.08.04,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM G.07.19 EEPROM G.07.20,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM G.07.19 EEPROM G.08.03,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM G.07.19 EEPROM G.08.04,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM G.08.08 EEPROM G.08.04,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM G.08.21 EEPROM G.08.21,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM H.07.15 EEPROM H.08.20,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM L.20.07 EEPROM L.20.24,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,0,FLIPPED,OK,FLIPPED",
        "HP JetDirect ROM R.22.01 EEPROM L.24.08,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,0,FLIPPED,OK,FLIPPED",
    "",
    "Linux Kernel,cpe:/o:linux:kernel",
        "Linux Kernel 2.6.11,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.6.10,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.6.9,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.6.8,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.6.7,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.6.6,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.6.5,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.6.4,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.6.3,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.6.2,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.6.1,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.6.0,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.30,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.29,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.28,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.27,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.26,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.25,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.24,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.23,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.22,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.21,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.20,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.19,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.18,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.17,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.16,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.15,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.14,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.13,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.12,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.11,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.10,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.9,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.8,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.7,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.6,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.5,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.4 (I),y,!0,0,!0,1,<255,y,0,<255,n,0,<255,n,0,<255,y,0xc0,1,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.4,y,!0,0,!0,1,<255,y,0,<255,n,0,<255,n,0,<255,y,0xc0,1,0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.3,y,!0,0,!0,1,<255,y,0,<255,n,0,<255,n,0,<255,y,0xc0,1,0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.2,y,!0,0,!0,1,<255,y,0,<255,n,0,<255,n,0,<255,y,0xc0,1,0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.1,y,!0,0,!0,1,<255,y,0,<255,n,0,<255,n,0,<255,y,0xc0,1,0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.0,y,!0,0,!0,1,<255,y,0,<255,n,0,<255,n,0,<255,y,0xc0,1,0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.26,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.25,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.24,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.23,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.22,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.21,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.20,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.19,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.18,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.17,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.16,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.15,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.14,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.13,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.12,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.11,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.10,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.9,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.8,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.7,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.6,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.5,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.4,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.3,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.2,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.1,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.0,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.0.36,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.0.34,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.0.30,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
    "",
    "Microsoft Windows,cpe:/o:microsoft:windows",
        "Microsoft Windows 2003 Server Enterprise Edition,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,>64,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 2003 Server Standard Edition,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,>64,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows XP SP2,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,>64,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows XP SP1,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows XP,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 2000 Server Service Pack 4,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 2000 Server Service Pack 3,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 2000 Server Service Pack 2,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 2000 Server Service Pack 1,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 2000 Server,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 2000 Workstation SP4,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 2000 Workstation SP3,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 2000 Workstation SP2,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 2000 Workstation SP1,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 2000 Workstation,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows Millennium Edition (ME),y,0,!0,!0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Server Service Pack 6a,y,0,!0,!0,1,<128,n,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Server Service Pack 5,y,0,!0,!0,1,<128,n,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Server Service Pack 4,y,0,!0,!0,1,<128,n,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Server Service Pack 3,y,0,!0,!0,1,<128,n,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Server Service Pack 2,y,0,!0,!0,1,<128,n,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Server Service Pack 1,y,0,!0,!0,1,<128,n,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Server,y,0,!0,!0,1,<128,n,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Workstation Service Pack 6a,y,0,!0,!0,1,<128,n,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Workstation Service Pack 5,y,0,!0,!0,1,<128,n,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Workstation Service Pack 4,y,0,!0,!0,1,<128,n,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Workstation Service Pack 3,y,0,!0,!0,1,<128,n,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Workstation Service Pack 2,y,0,!0,!0,1,<128,n,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Workstation Service Pack 1,y,0,!0,!0,1,<128,n,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Workstation,y,0,!0,!0,1,<128,n,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 98 Second Edition (SE),y,0,!0,!0,1,<128,y,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 98,y,0,!0,!0,1,<128,y,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 95,y,0,!0,!0,1,<32,n,!0,<32,y,!0,<32,n,!0,<32,y,0,0,!0,8,<32,OK,OK,OK,OK,OK",
    "",
    "NetBSD,cpe:/o:netbsd:netbsd",
        "NetBSD 2.0,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.6.2,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.6.1,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.6,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.5.3,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.5.2,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.5.1,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.5,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.4.3,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.4.2,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.4.1,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.4,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.3.3,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,0,FLIPPED,OK,FLIPPED",
        "NetBSD 1.3.2,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,0,FLIPPED,OK,FLIPPED",
        "NetBSD 1.3.1,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,0,FLIPPED,OK,FLIPPED",
        "NetBSD 1.3,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,0,FLIPPED,OK,FLIPPED",
    "",
    "OpenBSD,cpe:/o:openbsd:openbsd",
        "OpenBSD 3.7,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "OpenBSD 3.6,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "OpenBSD 3.5,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "OpenBSD 3.4,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "OpenBSD 3.3,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,BAD,OK,<20,OK",
        "OpenBSD 3.2,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,BAD,OK,<20,OK",
        "OpenBSD 3.1,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,BAD,OK,<20,OK",
        "OpenBSD 3.0,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,BAD,OK,<20,OK",
        "OpenBSD 2.9,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,<20,OK",
        "OpenBSD 2.8,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,<20,OK",
        "OpenBSD 2.7,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,<20,OK",
        "OpenBSD 2.6,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,<20,OK",
        "OpenBSD 2.5,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "OpenBSD 2.4,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,0,FLIPPED,OK,FLIPPED",
    "",
    "Sun Solaris,cpe:/o:sun:sunos",
        "Sun Solaris 10 (SunOS 5.10),y,!0,!0,!0,1,<255,n,!0,<255,y,!0,<255,n,!0,<255,y,0,1,!0,64,<255,OK,OK,OK,OK,OK",
        "Sun Solaris 9 (SunOS 5.9),y,!0,!0,!0,1,<255,y,!0,<255,y,!0,<255,n,!0,<255,y,0,1,!0,64,<255,OK,OK,OK,OK,OK",
        "Sun Solaris 8 (SunOS 2.8),y,!0,!0,!0,1,<255,y,!0,<255,y,!0,<255,n,!0,<255,y,0,1,!0,64,<255,OK,OK,OK,OK,OK",
        "Sun Solaris 7 (SunOS 2.7),y,!0,!0,!0,1,<255,y,!0,<255,y,!0,<255,n,!0,<255,y,0,1,!0,64,<255,OK,OK,OK,OK,OK",
        "Sun Solaris 6 (SunOS 2.6),y,!0,!0,!0,1,<255,y,!0,<255,y,!0,<255,n,!0,<255,y,0,1,!0,64,<255,OK,OK,OK,OK,OK",
        "Sun Solaris 2.5.1,y,!0,!0,!0,1,<255,y,!0,<255,y,!0,<255,n,!0,<255,y,0,1,!0,64,<255,OK,OK,OK,OK,OK",
    ""
);


function _TTL(ttl) {
    if (ttl <= 32)       num = 32;
    else if (ttl <= 64)  num = 64;
    else if (ttl <= 128) num = 128;
    else                 num = 255;

    return "<" + num;
}


# ModuleA()
#
#   ICMP Echo probe
#   Sends an ICMP Echo Request and generates a fingerprint from returned
#   packet's IP and ICMP headers.

function ModuleA() {

    # We might already know from ping_host.nasl that the target is not answering
    # to ICMP Echo request so directly return right away. This saves 2 seconds
    # for such a target.
    if( get_kb_item( "ICMPv4/EchoRequest/failed" ) ) return "n,,,,,";

    ICMP_ECHO_REQUEST = 8;

    # We will set the IP_ID to constant number. Further more that number
    # needs to be symmetric so we can easily work around the NASL bug.
    # The bug comes from get_ip_element() when we try to extract IP_ID
    # field...the IP_ID field comes out flipped. For example: SENT
    # IP_ID:0xAABB, extracted RECV IP_ID: 0xBBAA

    IP_ID = 0xBABA;

    ICMP_ID = rand() % 65536;
    ip_packet =
        forge_ip_packet(ip_tos : 6,
                        ip_id  : IP_ID,
                        ip_off : IP_DF,        # DON'T FRAGMENT flag
                        ip_p   : IPPROTO_ICMP,
                        ip_src : this_host());

    icmp_packet =
        forge_icmp_packet(icmp_type : ICMP_ECHO_REQUEST,
                          icmp_code : 123,
                          icmp_seq  : 256,
                          icmp_id   : ICMP_ID,
                          ip        : ip_packet);
    attempt = ATTEMPTS;
    ret = NULL;
    while (!ret && attempt--) {

        # pcap filter matches the ICMP Echo Reply packet with the same
        # ID as the original Echo Request packet

        filter = "icmp and dst host " + this_host() +
                " and src host " + get_host_ip() +
                " and icmp[0] = 0" +
                 " and icmp[4:2] = " + ICMP_ID;

        ret = send_packet(icmp_packet, pcap_active : TRUE,
                pcap_filter : filter, pcap_timeout : 1);
    }

    # icmp_echo_reply
    # icmp_echo_code
    # icmp_echo_ip_id
    # icmp_echo_tos_bits
    # icmp_echo_df_bit
    # icmp_echo_reply_ttl

    result = "";
    if (ret) {
        passed = 1;
        result = "y";

        if (get_icmp_element(element : "icmp_code", icmp : ret) == 0)
            result += ",0";
        else
            result += ",!0";

        received_id = get_ip_element(element : "ip_id", ip : ret);
        if (received_id == 0)
            result += ",0";
        else if (received_id == IP_ID)
            result += ",SENT";
        else
            result += ",!0";

        if (get_ip_element(element : "ip_tos", ip : ret) == 0)
            result += ",0";
        else
            result += ",!0";

        if (get_ip_element(element : "ip_off", ip : ret) & IP_DF)
            result += ",1";
        else
            result += ",0";

        ttl = get_ip_element(element : "ip_ttl", ip : ret);
        ttl = _TTL(ttl);

        result += "," + ttl;
    } else {

        # ICMP Echo Reply not received

        result = "n,,,,,";
    }

    return result;
}


# ModuleB()
#
#   ICMP Timestamp probe
#   Sends an ICMP Timestamp packet and generates a fingerprint from returned
#   packet's (ICMP Timestamp Reply) IP and ICMP headers.

function ModuleB() {
    ICMP_TIMESTAMP = 13;
    IP_ID = 0xBABA;
    ICMP_ID = rand() % 65536;

    ip_packet =
        forge_ip_packet(ip_id  : IP_ID,
                        ip_p   : IPPROTO_ICMP,
                        ip_src : this_host());

    icmp_packet =
        forge_icmp_packet(icmp_type : ICMP_TIMESTAMP,
                          icmp_id   : ICMP_ID,
                          ip        : ip_packet);

    attempt = ATTEMPTS;
    ret = NULL;
    while (!ret && attempt--) {
        ret = send_packet(icmp_packet, pcap_active : TRUE, pcap_timeout : 1,
            pcap_filter :
                "icmp and dst host " + this_host() +
                " and src host " + get_host_ip() +
                " and icmp[0] = 14" +
                " and icmp[4:2] = " + ICMP_ID);
    }

    # icmp_timestamp_reply
    # icmp_timestamp_reply_ip_id
    # icmp_timestamp_reply_ttl

    result = "";
    if (ret) {
        passed = 1;
        result += "y";

        received_id = get_ip_element(element : "ip_id", ip : ret);
        if (received_id == 0)
            result += ",0";
        else if (received_id == IP_ID)
            result += ",SENT";
        else
            result += ",!0";

        ttl = get_ip_element(element : "ip_ttl", ip : ret);
        ttl = _TTL(ttl);

        result += "," + ttl;
    } else {
        # For later use in e.g. 2011/gb_icmp_timestamps.nasl
        set_kb_item( name:"ICMPv4/TimestampRequest/failed", value:TRUE );
        result += "n,,";
    }

    return result;
}


# ModuleC()
#
#   ICMP Address Mask probe
#   Sends an ICMP Address Mask Request and generates a fingerprint from
#   returned packet's IP and ICMP headers.

function ModuleC() {
    ICMP_ADDRMASK = 17;
    IP_ID = 0xBABA;
    ICMP_ID = rand() % 65536;

    ip_packet =
        forge_ip_packet(ip_id  : IP_ID,
                        ip_p   : IPPROTO_ICMP,
                        ip_src : this_host());

    icmp_packet =
        forge_icmp_packet(icmp_type : ICMP_ADDRMASK,
                          icmp_id   : ICMP_ID,
                          data      : crap(length:4, data:raw_string(0)),
                          ip        : ip_packet);

    attempt = ATTEMPTS;
    ret = NULL;
    while (!ret && attempt--) {
        ret = send_packet(icmp_packet, pcap_active : TRUE, pcap_timeout : 1,
            pcap_filter :
                "icmp and dst host " + this_host() +
                " and src host " + get_host_ip() +
                " and icmp[0] = 18" +
                " and icmp[4:2] = " + ICMP_ID);
    }

    # icmp_addrmask_reply
    # icmp_addrmask_reply_ip_id
    # icmp_addrmask_reply_ttl

    result = "";
    if (ret) {
        passed = 1;
        result += "y";

        received_id = get_ip_element(element : "ip_id", ip : ret);
        if (received_id == 0)
            result += ",0";
        else if (received_id == IP_ID)
            result += ",SENT";
        else
            result += ",!0";

        ttl = get_ip_element(element : "ip_ttl", ip : ret);
        ttl = _TTL(ttl);

        result += "," + ttl;
    } else {
        # For later use by other NVTs
        set_kb_item( name:"ICMPv4/AddressMaskRequest/failed", value:TRUE );
        result += "n,,";
    }

    return result;
}


# ModuleD()
#
#   ICMP Info Request probe

function ModuleD() {
    ICMP_INFOREQ = 15;
    IP_ID = 0xBABA;
    ICMP_ID = rand() % 65536;

    ip_packet =
        forge_ip_packet(ip_id  : IP_ID,
                        ip_p   : IPPROTO_ICMP,
                        ip_src : this_host());

    icmp_packet =
        forge_icmp_packet(icmp_type : ICMP_INFOREQ,
                          icmp_id   : ICMP_ID,
                          ip        : ip_packet);

    attempt = ATTEMPTS;
    ret = NULL;
    while (!ret && attempt--) {
        ret = send_packet(icmp_packet, pcap_active : TRUE, pcap_timeout : 1,
            pcap_filter :
                "icmp and dst host " + this_host() +
                " and src host " + get_host_ip() +
                " and icmp[0] = 16" +
                " and icmp[4:2] = " + ICMP_ID);
    }

    # icmp_info_reply
    # icmp_info_reply_ip_id
    # icmp_info_reply_ttl

    result = "";
    if (ret) {
        passed = 1;
        result += "y";

        received_id = get_ip_element(element : "ip_id", ip : ret);
        if (received_id == 0)
            result += ",0";
        else if (received_id == IP_ID)
            result += ",SENT";
        else
            result += ",!0";

        ttl = get_ip_element(element : "ip_ttl", ip : ret);
        ttl = _TTL(ttl);

        result += "," + ttl;
    } else {
        # For later use by other NVTs
        set_kb_item( name:"ICMPv4/InfoRequest/failed", value:TRUE );
        result = "n,,";
    }

    return result;
}


# ModuleE()
#
#   ICMP Port Unreachable probe

function ModuleE() {
    ICMP_UNREACH_DEF_PORT = 65534;
    IP_ID = 0xBABA;
    ICMP_ID = rand() % 65536;

    ip_packet =
        forge_ip_packet(ip_id  : IP_ID,
                        ip_p   : IPPROTO_UDP,
                        ip_off : IP_DF,
                        ip_src : this_host());
    attempt = ATTEMPTS;
    ret = NULL;
    while (!ret && attempt--) {
        dport = ICMP_UNREACH_DEF_PORT - attempt;
        udp_packet =
            forge_udp_packet(
                                data     : crap(70),
                                ip       : ip_packet,
                                uh_dport : dport,
                                uh_sport : 53
                             );

        # ICMP Port Unreachable packet contains our sent packet
        ret = send_packet(udp_packet, pcap_active : TRUE, pcap_timeout : 1,
            pcap_filter :
                "icmp and dst host " + this_host() +
                " and src host " + get_host_ip() +
                " and icmp[0] = 3" +
                " and icmp[1:1] = 3 " +
                " and icmp[30:2] = " + dport);

    }

    # icmp_unreach_reply
    # icmp_unreach_precedence_bits
    # icmp_unreach_df_bit
    # icmp_unreach_ip_id
    # icmp_unreach_echoed_dtsize
    # icmp_unreach_reply_ttl
    # icmp_unreach_echoed_udp_cksum
    # icmp_unreach_echoed_ip_cksum
    # icmp_unreach_echoed_ip_id
    # icmp_unreach_echoed_total_len
    # icmp_unreach_echoed_3bit_flags

    result = "";
    if (ret) {
        passed = 1;

        # IP_Header_of_the_UDP_Port_Unreachable_error_message

        result += "y";

        # icmp_unreach_precedence_bits = 0xc0, 0, (hex num)

        tos = get_ip_element(ip:ret, element:"ip_tos");
        if (tos == 0xc0)
            result += ",0xc0";
        else if (tos == 0)
            result += ",0";
        else
            result += ",!0";

        # icmp_unreach_df_bit = [0 , 1 ]
        # we cannont access only df bit or 3bitflags. we access
        # 3_bit_flags + frag_offset

        _3bit_flag_frag_off = get_ip_element(ip:ret, element:"ip_off");
        if (_3bit_flag_frag_off & IP_DF)
            result += ",1";
        else
            result += ",0";

        #icmp_unreach_ip_id = [0, !0, SENT]

        received_id = get_ip_element(ip:ret, element:"ip_id");
        if (received_id == IP_ID)
            result += ",SENT";
        else if (received_id == 0)
            result += ",0";
        else
            result += ",!0";

        #icmp_unreach_echoed_dtsize = [8, 64, >64]

        echoed_dtsize = get_ip_element(ip:ret, element:"ip_len") - 20;
        if (echoed_dtsize == 64)
            reslt += ",64";
        else if (echoed_dtsize > 64)
            result += ",>64";
        else if (echoed_dtsize == 8)
            result += ",8";
        else
            result += "," + echoed_dtsize;

        # Original_data_echoed_with_the_UDP_Port_Unreachable_error_message
        # we bypass the ip + icmp_unreach and we get to our original packet!

        hl = get_ip_element(ip:ret, element:"ip_hl");
        echoed_ip_packet = substr(ret, hl*4+8);
        echoed_ip_packet_hl = get_ip_element(ip:echoed_ip_packet, element:"ip_hl");
        echoed_udp_packet = substr(echoed_ip_packet, echoed_ip_packet_hl*4);

        # icmp_unreach_reply_ttl = [>< decimal num]

        reply_ttl = get_ip_element(element : "ip_ttl", ip : ret);
        ip_packet_ttl = get_ip_element(ip: ip_packet, element : "ip_ttl");
        echoed_ip_packet_ttl = get_ip_element(ip:echoed_ip_packet, element:"ip_ttl");
        real_ttl = reply_ttl + ip_packet_ttl - echoed_ip_packet_ttl ;

        if (real_ttl <= 32)
            result += ",<32";
        else if (real_ttl <= 60)
            result += ",<60";
        else if (real_ttl <= 64)
            result += ",<64";
        else if (real_ttl <= 128)
            result += ",<128";
        else
            result += ",<255";

        # Extracting checksums from echoed datagram
        # icmp_unreach_echoed_udp_cksum = [0, OK, BAD]

        echoed_udp_checksum = get_udp_element(udp: echoed_udp_packet, element:"uh_sum");
        udp_packet_checksum = get_udp_element(udp: udp_packet, element: "uh_sum");

        if (echoed_udp_checksum == udp_packet_checksum)
            result += ",OK";
        else if (echoed_udp_checksum == 0)
            result += ",0";
        else
            result += ",BAD";

        # icmp_unreach_echoed_ip_cksum  = [0, OK, BAD]

        echoed_ip_checksum = get_ip_element(ip:echoed_ip_packet, element:"ip_sum");

        # making a copy of the original udp_packet with updated ttl field
        # to the echoed_ip_packet's ttl and then extracting ip checksum
        # from udp_packet_copy

        ip_packet_copy = forge_ip_packet(ip_id  : IP_ID,
                            ip_p   : IPPROTO_UDP,
                            ip_off : IP_DF,
                            ip_src : this_host(),
                            ip_ttl : get_ip_element(ip:echoed_ip_packet, element:"ip_ttl"));
        udp_packet_copy =
            forge_udp_packet(
                                data     : crap(70),
                                ip       : ip_packet_copy,
                                uh_dport : dport,
                                uh_sport : 53
                             );

        ip_packet_copy_checksum = get_ip_element(ip:udp_packet_copy, element: "ip_sum");

        if (echoed_ip_checksum == ip_packet_copy_checksum)
            result += ",OK";
        else if (echoed_ip_checksum == 0)
            result += ",0";
        else
            result += ",BAD";

        # icmp_unreach_echoed_ip_id = [OK, FLIPPED]
        original_ip_id = substr(ip_packet, 4,5);
        echoed_ip_id = substr(echoed_ip_packet, 4,5);
        # flipp the two bytes
        flipped_original_ip_id = raw_string(substr(original_ip_id, 1), substr(original_ip_id, 0, 0));
        # end flipp

        if (original_ip_id == echoed_ip_id)
            result += ",OK";
        else if (original_ip_id == flipped_original_ip_id)
            result += ",FLIPPED";
        else
            result += ",BAD";

        # icmp_unreach_echoed_total_len = [>20, OK, <20]

        echoed_total_len = get_ip_element(ip:echoed_ip_packet, element: "ip_len");
        original_total_len = get_ip_element(ip:udp_packet, element: "ip_len");

        if (echoed_total_len == original_total_len)
            result += ",OK";
        else if (echoed_total_len == original_total_len - 20)
            result += ",<20";
        else if (echoed_total_len == original_total_len + 20)
            result += ",>20";
        else
            result += ",unexpected";

        # icmp_unreach_echoed_3bit_flags = [OK, FLIPPED]

        echoed_ip_frag_off = get_ip_element(ip:echoed_ip_packet, element: "ip_off");
        original_ip_frag_off = get_ip_element(ip:ip_packet, element: "ip_off");

        # flipp the two bytes

        flipped_original_ip_frag_off = raw_string(substr(original_ip_frag_off, 1), substr(original_ip_frag_off, 0, 0));

        #end flipp

        if (echoed_ip_frag_off == original_ip_frag_off)
            result += ",OK";
        else if (echoed_ip_frag_off == flipped_original_ip_frag_off)
            result += ",FLIPPED";
        else
            result += ",unexpected";
    } else {
        # For later use by other NVTs
        set_kb_item( name:"ICMPv4/UDPPortUnreachable/failed", value:TRUE );
        result += "n,,,,,,,,,,";
    }

    return result;
}

#------------------------------------------------------------------------------

result =
    ModuleA() + "," +
    ModuleB() + "," +
    ModuleC() + "," +
    ModuleD() + "," +
    ModuleE();

# display(result, '\n');

fp = split(result, sep:",", keep:0);


best_score     = 0;
best_os        = make_array();
store_sections = FALSE;

if (passed) {

    section_title = "";

    foreach line (FINGERPRINTS) {

        if (section_title == "") {
            extract = split(line, sep:",", keep:0);
            section_title = extract[0];
            section_cpe = extract[1];
            continue;
        } else if (line == "") {
            section_title = "";
            continue;
        } else {

            ar = split(line, sep:",", keep:0);

            name = ar[0];
            score = 0;
            total = 0;

            for (i = 0; i < max_index(fp); ++i) {
                # skip unset value
                if (isnull(fp[i]) || fp[i] == "")
                    continue;

                total += 1;

                if (!isnull(ar[i+1]) && ar[i+1] != "" && ar[i+1] == fp[i])
                    score += 1;
            }

            if (total > 0)
                percentage = 100*score/total;

            if (percentage > best_score) {
                best_score = percentage;
                best_os = make_array(name, section_cpe);
                store_sections = FALSE;
            } else if (percentage == best_score) {
                # In case we have several matches, then just use the section title
                if (!store_sections) {
                    best_os = make_array(section_title, section_cpe);
                    store_sections = TRUE;
                } else {
                    best_os[section_title] = section_cpe;
                }
            }
        }
    }
}

if( best_score == 0 ) {
  best_os = "Unknown";
}

if( typeof( best_os ) == "array") {

  # Creating report before iterating later again as we want to report multiple detected OS within one single report
  report = '\n(' + best_score + '% confidence)\n';
  foreach ostitle( keys( best_os ) ) {
    report += '\n' + ostitle;
  }

  # Counter for later as we don't have a port registered for ICMP
  i = 0;

  foreach ostitle( keys( best_os ) ) {

    i++;
    set_kb_item( name:"Host/OS/ICMP", value:ostitle );
    set_kb_item( name:"Host/OS/ICMP/Confidence", value:best_score );

    if( "linux" >< tolower( report ) || "bsd" >< tolower( report ) || "mac os x" >< tolower( report ) ) {
      # Some systems not answering to ICMP are often identified as "HP JetDirect/Linux Kernel/Microsoft Windows"
      # so check here if this is the case and don't set the kb
      if( "windows" >!< tolower( report ) ) {
        runs_key = "unixoide";
      }
    }

    if( "windows" >< tolower( report ) ) {
      # Some systems not answering to ICMP are often identified as "HP JetDirect/Linux Kernel/Microsoft Windows"
      # so check here if this is the case and don't set the kb
      if( "linux" >!< tolower( report ) && "bsd" >!< tolower( report ) && "mac os x" >!< tolower( report ) ) {
        runs_key = "windows";
      }
    }

    # nb: Setting the runs_key to unixoide makes sure that we still schedule NVTs using Host/runs_unixoide as a fallback
    if( ! runs_key ) runs_key = "unixoide";

    register_and_report_os( os:ostitle, cpe:best_os[ostitle], banner_type:"ICMP based OS fingerprint", desc:SCRIPT_DESC, port:i, proto:"icmp", runs_key:runs_key );
  }
} else {

  # No match found (best_score == 0 from above) so don't register the host detail here
  set_kb_item( name:"Host/OS/ICMP", value:best_os );
  set_kb_item( name:"Host/OS/ICMP/Confidence", value:best_score );
}

exit( 0 );
