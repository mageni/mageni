# OpenVAS Vulnerability Test
# $Id: toolcheck.nasl 13794 2019-02-20 14:59:32Z cfischer $
# Description: Initializing routine for checking presence of helper tools
#
# Authors:
# Jan-Oliver Wagner <Jan-Oliver.Wagner@greenbone.net>
# Felix Wolfsteller <felix.wolfsteller@greenbone.net>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810000");
  script_version("$Revision: 13794 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-20 15:59:32 +0100 (Wed, 20 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-08-17 09:05:44 +0200 (Mon, 17 Aug 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Availability of scanner helper tools");
  script_category(ACT_INIT);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");

  script_add_preference(name:"Silent tool check", type:"checkbox", value:"yes");
  #TBD: Set the default of Silent tool check above to "no" once GOS 3.1 has been deprecated? The executed_on_gos below is working on GOS 4.2+.
  script_add_preference(name:"Silent tool check on Greenbone OS (GOS)", type:"checkbox", value:"yes");

  script_tag(name:"summary", value:"This routine checks for the presence of various tools that
  support the scan engine and the version of the scan engine itself. If some tools are not accessible
  for the scan engine, one or more NVTs could not be executed properly.

  The consequence might be that certain vulnerabilities or additional (compliance) tests are missed because
  respective tests are not performed.

  Note: The tool check is always 'silent' by default when running on a Greenbone OS (GOS) based installation
  like the Greenbone Security Manager (GSM) or Greenbone Community Edition (GCE). Both installation
  are shipping all required / supported tools by default.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("version_func.inc");

perform_check = script_get_preference("Perform tool check");
if(perform_check == "no")
  exit(0);

silent_check = script_get_preference("Silent tool check");
silent_gos   = script_get_preference("Silent tool check on Mageni Appliance");
is_gos       = executed_on_gos();

# nb: See Note in the description.
if(is_gos && silent_gos == "yes")
  silent_check = "yes";

all_tools_available = TRUE;
up2date_engine = TRUE;
min_expected_engine_ver = "8.0";

# TBD: Remove completely as no ovaldi support / the OVAL definitions seems to be available anymore.
#sufficient_ovaldi_found = FALSE;
#if(find_in_path("ovaldi")) {
#  ovaldi_out = pread(cmd:"ovaldi", argv:make_list("ovaldi", "-h"));
#  foreach line(split(ovaldi_out)) {
#    v = eregmatch(string:line, pattern:'Version: ([0-9.]*) Build: ([0-9.]*)');
#    if(!isnull(v)) {
#      found_version = v[1] + '.';
#      found_version = found_version + v[2];
#      if(version_is_greater_equal(version:found_version, test_version:"5.5.23")) {
#        sufficient_ovaldi_found = TRUE;
#        break;
#      }
#    }
#  }
#}

#if(!sufficient_ovaldi_found) {
#  set_kb_item(name:"Tools/Missing/ovaldi", value:TRUE);
#  tools_summary += '\n\nTool:   ovaldi 5.5.23 or newer\n';
#  tools_summary += 'Effect: No NVTs of family \'OVAL definitions\' will be executed. This family is only visible in case your installation includes OVAL files.';
#  all_tools_available = FALSE;
#} else {
#  set_kb_item(name:"Tools/Present/ovaldi", value:TRUE);
#}

# (built-in) WMI support
if(wmi_versioninfo()) {
  set_kb_item(name:"Tools/Present/wmi", value:TRUE);
} else {
  tools_summary += '\n\nTool:   WMI Client (Scanner not build with extended WMI support via the openvas-smb module)\n';
  tools_summary += 'Effect: Any NVTs that do rely on the built-in WMI functionality will not be executed. Most likely reduced are Authenticated Scans due missing ';
  tools_summary += 'Local Security Checks (LSC), compliance tests and OVAL NVTs.\n';
  tools_summary += 'Note:   If you did not provide SMB credentials or do not scan host with Windows operating systems, the absence will not reduce the number of executed NVTs.';
  set_kb_item(name:"Tools/Missing/wmi", value:TRUE);
  all_tools_available = FALSE;
}

# (built-in) SMB support
if(smb_versioninfo()) {
  set_kb_item(name:"Tools/Present/smb", value:TRUE);
} else {
  tools_summary += '\n\nTool:   SMB Client (Scanner not build with extended WMI support via the openvas-smb module)\n';
  tools_summary += 'Effect: Any NVTs that do rely on the built-in SMB functionality will not be executed. Most likely reduced are Authenticated Scans due missing ';
  tools_summary += 'Local Security Checks (LSC), compliance tests and OVAL NVTs.\n';
  tools_summary += 'Note:   If you did not provide SMB credentials or do not scan host with Windows operating systems, the absence will not reduce the number of executed NVTs.';
  set_kb_item(name:"Tools/Missing/smb", value:TRUE);
  all_tools_available = FALSE;
}

# Scanner needs to be build against libsnmp, e.g. snmp_func.inc
if(defined_func("snmpv3_get")) {
  set_kb_item(name:"Tools/Present/libsnmp", value:TRUE);
} else {
  tools_summary += '\n\nTool:   SNMP Client (Scanner not build with libsnmp support)\n';
  tools_summary += 'Effect: Advanced SNMP checks and connections to SNMPv3 only services will fail.\n';
  tools_summary += 'Note:   If you do not scan host with SNMP services, the absence will not reduce the number of executed NVTs.';
  set_kb_item(name:"Tools/Missing/libsnmp", value:TRUE);
  all_tools_available = FALSE;
}

sufficient_nmap_found = FALSE;
if(find_in_path("nmap")) {
  nmap_v_out = pread(cmd:"nmap", argv:make_list("nmap", "-V"));
  if(nmap_v_out) {
    ver = ereg_replace(pattern:".*nmap version ([0-9.]+).*", string:nmap_v_out, replace:"\1", icase:TRUE);
    if(ver == nmap_v_out)
      ver = NULL;
  }

  if(ver =~ "^[4-9]\.") {

    sufficient_nmap_found = TRUE;

    if(version_is_equal(version:ver, test_version:"5.21")) {
      nmap_check_nse_support = pread(cmd:"nmap", argv:make_list("nmap", "--help"));
      if(nmap_check_nse_support != 0) {
        if("script-updatedb" >!< nmap_check_nse_support) {
          tools_summary += '\n\nTool:   Nmap 5.21\n';
          tools_summary += 'Effect: Nmap was build without support for NSE scripts. NVTs of the \'Nmap NSE\' and \'Nmap NSE net\' families will not work.';
        } else {
          set_kb_item(name:"Tools/Present/nmap5.21", value:TRUE);
        }
      }
    }

    if(version_is_equal(version:ver, test_version:"5.51")) {
      nmap_check_nse_support = pread(cmd:"nmap", argv:make_list("nmap", "--help"));
      if(nmap_check_nse_support != 0) {
        if("script-updatedb" >!< nmap_check_nse_support) {
          tools_summary += '\n\nTool:   Nmap 5.51\n';
          tools_summary += 'Effect: Nmap was build without support for NSE scripts. NVTs of the \'Nmap NSE\' and \'Nmap NSE net\' families will not work.';
        } else {
          set_kb_item(name:"Tools/Present/nmap5.51", value:TRUE);
        }
      }
    }

    if(version_is_equal(version:ver, test_version:"6.01")) {
      nmap_check_nse_support = pread(cmd:"nmap", argv:make_list("nmap", "--help"));
      if(nmap_check_nse_support != 0) {
        if("script-updatedb" >!< nmap_check_nse_support) {
          tools_summary += '\n\nTool:   Nmap 6.01\n';
          tools_summary += 'Effect: Nmap was build without support for NSE scripts. NVTs of the \'Nmap NSE\' and \'Nmap NSE net\' families will not work.';
        } else {
          set_kb_item(name:"Tools/Present/nmap6.01", value:TRUE);
        }
      }
    }
  }
}

if(sufficient_nmap_found == TRUE) {
  set_kb_item(name:"Tools/Present/nmap", value:TRUE);
} else {
  tools_summary += '\n\nTool:   nmap 4.0 or newer\n';
  tools_summary += 'Effect: Port scanning and service detection based on nmap is not available.';
  set_kb_item(name:"Tools/Missing/nmap", value:TRUE);
  all_tools_available = FALSE;
}

# gcf/remote-pwcrack-options.nasl
# TODO: Migh find a pd executable from "pure data", disambiguate
if(!is_gos && find_in_path("pd")) {
  set_kb_item(name:"Tools/Present/pd", value:TRUE);
  set_kb_item(name:"Tools/Present/pd_or_ncrack", value:TRUE);
} else {
  set_kb_item(name:"Tools/Missing/pd", value:TRUE);
  set_kb_item(name:"Tools/Missing/pd_or_ncrack", value:TRUE);
  tools_summary += '\n\nTool:   pd/phrasendrescher\n';
  tools_summary += 'Effect: The phrasendrescher wrapper will not deliver results. This NVT could otherwise attempt to find SSH accounts and passwords via brute-force attempts.\n';
  tools_summary += 'Note:   This wrapper is not available in the Greenbone Security Feed (GSF).\n';
  tools_summary += 'Note:   The tool is not available on a Greenbone OS (GOS) based installation like the Greenbone Security Manager (GSM) or Greenbone Community Edition (GCE).';
  all_tools_available = FALSE;
}

# gcf/remote-pwcrack-options.nasl
if(!is_gos && find_in_path("ncrack")) {
  set_kb_item(name:"Tools/Present/ncrack", value:TRUE);
  set_kb_item(name:"Tools/Present/pd_or_ncrack", value:TRUE);
} else {
  set_kb_item(name:"Tools/Missing/ncrack", value:TRUE);
  set_kb_item(name:"Tools/Missing/pd_or_ncrack", value:TRUE);
  tools_summary += '\n\nTool:   ncrack\n';
  tools_summary += 'Effect: ncrack wrappers will not deliver results. The ncrack wrappers could otherwise attempt to find FTP, SSH and Telnet accounts and passwords via brute-force attempts.\n';
  tools_summary += 'Note:   The wrapper for this tool is not available in the Greenbone Security Feed (GSF).\n';
  tools_summary += 'Note:   The tool is not available on a Greenbone OS (GOS) based installation like the Greenbone Security Manager (GSM) or Greenbone Community Edition (GCE).';
  all_tools_available = FALSE;
}

# gcf/portbunny.nasl
if(!is_gos && find_in_path("portbunny")) {
  set_kb_item(name:"Tools/Present/portbunny", value:TRUE);
} else {
  set_kb_item(name:"Tools/Missing/portbunny", value:TRUE);
  tools_summary += '\n\nTool:   portbunny\n';
  tools_summary += 'Effect: Optional port scanning based on portbunny is not available.\n';
  tools_summary += 'Note:   The wrapper for this tool is not available in the Greenbone Security Feed (GSF).\n';
  tools_summary += 'Note:   The tool is not available on a Greenbone OS (GOS) based installation like the Greenbone Security Manager (GSM) or Greenbone Community Edition (GCE).';
  all_tools_available = FALSE;
}

# 2008/pnscan.nasl
if(find_in_path("pnscan")) {
  set_kb_item(name:"Tools/Present/pnscan", value:TRUE);
} else {
  set_kb_item(name:"Tools/Missing/pnscan", value:TRUE);
  tools_summary += '\n\nTool:   pnscan\n';
  tools_summary += 'Effect: Optional port scanning based on pnscan is not available.';
  all_tools_available = FALSE;
}

# gcf/portscan-strobe.nasl
if(!is_gos && find_in_path("strobe")) {
  set_kb_item(name:"Tools/Present/strobe", value:TRUE);
} else {
  set_kb_item(name:"Tools/Missing/strobe", value:TRUE);
  tools_summary += '\n\nTool:   strobe\n';
  tools_summary += 'Effect: Optional port scanning based on strobe is not available.\n';
  tools_summary += 'Note:   The wrapper for this tools is deprecated and is not available in the Greenbone Security Feed (GSF).\n';
  tools_summary += 'Note:   The tool is not available on a Greenbone OS (GOS) based installation like the Greenbone Security Manager (GSM) or Greenbone Community Edition (GCE).';
  all_tools_available = FALSE;
}

# gcf/amap.nasl
if(!is_gos) {
  amap6 = find_in_path("amap6");
  amap = find_in_path("amap");
}

if(amap6 || amap) {
  set_kb_item(name:"Tools/Present/amap", value:TRUE);
  if(amap6) {
    set_kb_item(name:"Tools/Present/amap/bin", value:"amap6");
  } else {
    set_kb_item(name:"Tools/Present/amap/bin", value:"amap");
  }
} else {
  set_kb_item(name:"Tools/Missing/amap", value:TRUE);
  tools_summary += '\n\nTool:   amap/amap6\n';
  tools_summary += 'Effect: Optional port scanning and service detection based on amap is not available.\n';
  tools_summary += 'Note:   The wrapper for this tool is not available in the Greenbone Security Feed (GSF).\n';
  tools_summary += 'Note:   The tool is not available on a Greenbone OS (GOS) based installation like the Greenbone Security Manager (GSM) or Greenbone Community Edition (GCE).';
  all_tools_available = FALSE;
}

# pre2008/snmpwalk_portscan.nasl
if(find_in_path("snmpwalk")) {
  set_kb_item(name:"Tools/Present/snmpwalk", value:TRUE);
} else {
  set_kb_item(name:"Tools/Missing/snmpwalk", value:TRUE);
  tools_summary += '\n\nTool:   snmpwalk\n';
  tools_summary += 'Effect: Optional port scanning based on snmpwalk is not available.';
  all_tools_available = FALSE;
}

# pre2008/ldapsearch.nasl
if(find_in_path("ldapsearch")) {
  set_kb_item(name:"Tools/Present/ldapsearch", value:TRUE);
} else {
  set_kb_item(name:"Tools/Missing/ldapsearch", value:TRUE);
  tools_summary += '\n\nTool:   ldapsearch\n';
  tools_summary += 'Effect: Advanced LDAP directory checks are not available.';
  all_tools_available = FALSE;
}

# gcf/gb_masscan.nasl
if(!is_gos && find_in_path("masscan")) {
  set_kb_item(name:"Tools/Present/masscan", value:TRUE);
} else {
  set_kb_item(name:"Tools/Missing/masscan", value:TRUE);
  tools_summary += '\n\nTool:   masscan\n';
  tools_summary += 'Effect: Optional port scanning based on masscan is not available.\n';
  tools_summary += 'Note:   The wrapper for this tool is not available in the Greenbone Security Feed (GSF).\n';
  tools_summary += 'Note:   The tool is not available on a Greenbone OS (GOS) based installation like the Greenbone Security Manager (GSM) or Greenbone Community Edition (GCE).';
  all_tools_available = FALSE;
}

# gcf/smbcl_getversion.nasl
if(!is_gos && find_in_path("smbclient")) {
  set_kb_item(name:"Tools/Present/smbclient", value:TRUE);
} else {
  set_kb_item(name:"Tools/Missing/smbclient", value:TRUE);
  tools_summary += '\n\nTool:   smbclient\n';
  tools_summary += 'Effect: The report might miss some informative data about the remote SMB server collected by the NVT \'SMB Test with \'smbclient\'\' (OID 1.3.6.1.4.1.25623.1.0.90011).\n';
  tools_summary += 'Note:   This tool is NOT required for Authenticated Scans against Windows operating systems.\n';
  tools_summary += 'Note:   The wrapper for this tool is not available in the Greenbone Security Feed (GSF).';
  all_tools_available = FALSE;
}

# nikto.nasl
niktopl = find_in_path("nikto.pl");
nikto = find_in_path("nikto");
if(niktopl || nikto) {
  set_kb_item(name:"Tools/Present/nikto", value:TRUE);
  if(niktopl) {
    set_kb_item(name:"Tools/Present/nikto/bin", value:"nikto.pl");
  } else {
    set_kb_item(name:"Tools/Present/nikto/bin", value:"nikto");
  }
} else {
  set_kb_item(name:"Tools/Missing/nikto", value:TRUE);
  tools_summary += '\n\nTool:   nikto.pl/nikto\n';
  tools_summary += 'Effect: It is not possible to run the two NVTs \'Nikto (NASL wrapper)\' (OID: 1.3.6.1.4.1.25623.1.0.14260) and ';
  tools_summary += '\'Starts nikto with Option -Tuning x016bc and write to KB\' (OID: 1.3.6.1.4.1.25623.1.0.96044).';
  all_tools_available = FALSE;
}

# 2009/remote-web-w3af.nasl
if(find_in_path("w3af_console")) {
  set_kb_item(name:"Tools/Present/w3af", value:TRUE);
} else {
  set_kb_item(name:"Tools/Missing/w3af", value:TRUE);
  tools_summary += '\n\nTool:   w3af (binary: w3af_console)\n';
  tools_summary += 'Effect: It is not possible to run the NVT \'w3af (NASL wrapper)\' (OID: 1.3.6.1.4.1.25623.1.0.80109).';
  all_tools_available = FALSE;
}

# gcf/dirb.nasl
if(!is_gos && find_in_path("dirb")) {
  set_kb_item(name:"Tools/Present/dirb", value:TRUE);
} else {
  set_kb_item(name:"Tools/Missing/dirb", value:TRUE);
  tools_summary += '\n\nTool:   DIRB\n';
  tools_summary += 'Effect: It is not possible to run the NVT \'DIRB (NASL wrapper)\' (OID: 1.3.6.1.4.1.25623.1.0.103079)\n';
  tools_summary += 'Note:   The wrapper for this tool is not available in the Greenbone Security Feed (GSF).';
  all_tools_available = FALSE;
}

# gcf/remote-web-arachni.nasl
if(!is_gos) {
  arachnirb = find_in_path("arachni.rb");
  arachni = find_in_path("arachni");
}

if(arachnirb || arachni) {
  set_kb_item(name:"Tools/Present/arachni", value:TRUE);
  if(arachnirb) {
    set_kb_item(name:"Tools/Present/arachni/bin", value:"arachni.rb");
  } else {
    set_kb_item(name:"Tools/Present/arachni/bin", value:"arachni");
  }
} else {
  set_kb_item(name:"Tools/Missing/arachni", value:TRUE);
  tools_summary += '\n\nTool:   arachni\n';
  tools_summary += 'Effect: It is not possible to run the NVT \'arachni (NASL wrapper)\' (OID: 1.3.6.1.4.1.25623.1.0.110001)\n';
  tools_summary += 'Note:   The wrapper for this tool is not available in the Greenbone Security Feed (GSF).';
  all_tools_available = FALSE;
}

# gcf/remote-web-wapiti.nasl
if(!is_gos && find_in_path("wapiti")) {
  set_kb_item(name:"Tools/Present/wapiti", value:TRUE);
} else {
  set_kb_item(name:"Tools/Missing/wapiti", value:TRUE);
  tools_summary += '\n\nTool:   wapiti\n';
  tools_summary += 'Effect: It is not possible to run the NVT \'wapiti (NASL wrapper)\' (OID: 1.3.6.1.4.1.25623.1.0.80110)\n';
  tools_summary += 'Note:   The wrapper for this tool is not available in the Greenbone Security Feed (GSF).';
  all_tools_available = FALSE;
}

# gb_host_alive_check* and sw_ssl_cert_get_hostname.nasl
ping = find_in_path("ping");
ping6 = find_in_path("ping6");
if(ping || ping6) {

  set_kb_item(name:"Tools/Present/ping", value:TRUE);

  # nb: There are differences between inetutils and iputils packages and versions.
  # Some packages have e.g. a ping6 binary, others just a symlink from ping6 to ping.
  #
  # First check if the ping command supports the -6/-4 parameter
  check = pread(cmd:"ping", argv:make_list("ping", "--usage"), cd:TRUE);
  if("Usage: ping" >< check && "64]" >< check)
    param64 = TRUE;

  if(TARGET_IS_IPV6()) {
    # If the -6 parameter is available explicitly specify it for the ping command and use only "ping"
    if(param64){
      ping_cmd = "ping";
      set_kb_item(name:"Tools/Present/ping/extra_cmd", value:"-6");
    } else {
      if(ping6)
        ping_cmd = "ping6";
      else
        ping_cmd = "ping";
    }
    set_kb_item(name:"Tools/Present/ping/bin", value:ping_cmd);
  } else {
    # If the -4 parameter is available explicitly specify it for the ping command
    if(param64)
      set_kb_item(name:"Tools/Present/ping/extra_cmd", value:"-4");
    else
      ping_cmd = "ping";
    set_kb_item(name:"Tools/Present/ping/bin", value:"ping");
  }
} else {
  set_kb_item(name:"Tools/Missing/ping", value:TRUE);
  tools_summary += '\n\nTool:   ping/ping6\n';
  tools_summary += 'Effect: Various NVTs are currently relying on the availability of the \'ping\' command.';
  all_tools_available = FALSE;
}

# gcf/ike-scan.nasl
if(!is_gos && find_in_path("ike-scan")) {
  set_kb_item(name:"Tools/Present/ike-scan", value:TRUE);
} else {
  set_kb_item(name:"Tools/Missing/ike-scan", value:TRUE);
  tools_summary += '\n\nTool:   ike-scan\n';
  tools_summary += 'Effect: It is not possible to run the NVT \'ike-scan (NASL wrapper)\' (OID: 1.3.6.1.4.1.25623.1.0.80000)\n';
  tools_summary += 'Note:   The wrapper for this tool is not available in the Greenbone Security Feed (GSF).';
  all_tools_available = FALSE;
}

# Various
if(find_in_path("openssl")) {
  set_kb_item(name:"Tools/Present/openssl", value:TRUE);
} else {
  set_kb_item(name:"Tools/Missing/openssl", value:TRUE);
  tools_summary += '\n\nTool:   openssl\n';
  tools_summary += 'Effect: Various NVTs of the \'IT-Grundschutz\' family currently rely on the availability of the \'openssl\' command.';
  all_tools_available = FALSE;
}

# GSHB/GSHB_Printer_SSL-TLS.nasl
if(find_in_path("sed")) {
  set_kb_item(name:"Tools/Present/sed", value:TRUE);
} else {
  set_kb_item(name:"Tools/Missing/sed", value:TRUE);
  tools_summary += '\n\nTool:   sed\n';
  tools_summary += 'Effect: The NVT \'Printer Test SSL/TLS\' (OID: 1.3.6.1.4.1.25623.1.0.96056) is currently relying on the availability of the \'sed\' command.';
  all_tools_available = FALSE;
}

# pre2008/netstat_portscan.nasl
if(find_in_path("netstat")) {
  set_kb_item(name:"Tools/Present/netstat", value:TRUE);
} else {
  set_kb_item(name:"Tools/Missing/netstat", value:TRUE);
  tools_summary += '\n\nTool:   netstat\n';
  tools_summary += 'Effect: Optional port scanning based on netstat when scanning the localhost is not available.';
  all_tools_available = FALSE;
}

# 2012/gb_rugged_operating_system_53215.nasl and GSHB/EL15/GSHB_M4_017.nasl
if(find_in_path("perl")) {
  set_kb_item(name:"Tools/Present/perl", value:TRUE);
} else {
  set_kb_item(name:"Tools/Missing/perl", value:TRUE);
  tools_summary += '\n\nTool:   perl\n';
  tools_summary += 'Effect: Various NVTs are currently relying on the availability of the \'perl\' command.';
  all_tools_available = FALSE;
}

# Send final summary as log information if "Silent tool check" is not "yes"
if(silent_check == "yes")
  exit(0);

if(OPENVAS_VERSION && OPENVAS_VERSION =~ "^[0-9]+\." && version_is_less(version:OPENVAS_VERSION, test_version:min_expected_engine_ver))
  up2date_engine = FALSE;
else if(!OPENVAS_VERSION)
  up2date_engine = NULL;

if(all_tools_available == FALSE) {
  report  = "The following tools are not accessible for the scan engine. Please contact the responsible administrator of the ";
  report += 'installation to make the missing tool(s) available.';
  report += tools_summary;
} else {
  report = "All checks for presence of scanner tools were successful. This means they are found and are sufficiently up-to-date.";
}

if(up2date_engine == FALSE)
  report += '\n\nThe check for an up-to-date scan engine version failed. Expected version: ' + min_expected_engine_ver + ' , Current version: ' + OPENVAS_VERSION;
else if(isnull(up2date_engine))
  report += '\n\nThe check for an up-to-date scan engine version failed. It was not possible to determine the version of the scan engine.';
else
  report += '\n\nThe check for an up-to-date scan engine version was successful. Minimum expected version: ' + min_expected_engine_ver + ', Current installed version: ' + OPENVAS_VERSION;

log_message(port:0, data:report);
exit(0);