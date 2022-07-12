###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_orangeworm_kwampirs_trojan_detect.nasl 12794 2018-12-13 14:36:15Z cfischer $
#
# Orangeworm Kwampirs Trojan Detection
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107306");
  script_version("$Revision: 12794 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-13 15:36:15 +0100 (Thu, 13 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-04-26 15:23:05 +0100 (Thu, 26 Apr 2018)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"cvss_base", value:"10.0");
  script_name("Orangeworm Kwampirs Trojan Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Malware");
  script_dependencies("gb_wmi_access.nasl");
  script_mandatory_keys("WMI/access_successful");

  script_xref(name:"URL", value:"https://www.symantec.com/blogs/threat-intelligence/orangeworm-targets-healthcare-us-europe-asia");
  script_xref(name:"URL", value:"http://www.virusresearch.org/kwampirs-trojan-removal/");

  script_tag(name:"summary", value:"The script tries to detect the Orangeworm Kwampirs Trojan via various known Indicators of Compromise (IOC).");

  script_tag(name:"insight", value:"The Orangeworm group is using a repurposed Trojan called Kwampirs to set up persistent remote access after they infiltrate
  victim organizations. Kwampirs is not especially stealthy and can be detected using indicators of compromise and activity on the target system. The Trojan
  evades hash-based detection by inserting a random string in its main executable so its hash is different on each system. However, Kwampirs uses consistent
  services names, configuration files, and similar payload DLLs on the target machine that can be used to detect it.");

  script_tag(name:"impact", value:"Trojan.Kwampirs is a Trojan horse that may open a back door on the compromised computer. It may also download potentially malicious files.");

  script_tag(name:"affected", value:"All Windows Systems.");

  script_tag(name:"solution", value:"A whole cleanup of the infected system is recommended.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("host_details.inc");
include("smb_nt.inc");

infos = kb_smb_wmi_connectinfo();
if( ! infos ) exit( 0 );

handle = wmi_connect( host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"] );
if( ! handle ) exit( 0 );

# nb: Make sure to update the foreach loop below if adding new fields here
query = "SELECT Description, DisplayName, Name, PathName FROM Win32_Service";
services = wmi_query( wmi_handle:handle, query:query );
wmi_close( wmi_handle:handle );
if( ! services ) exit( 0 );

services_list = split( services, keep:FALSE );

foreach service( services_list ) {

  if( service == "Description|DisplayName|Name|PathName" ) continue; # nb: Just ignoring the header, make sure to update this if you add additional fields to the WMI query above

  service_split = split( service, sep:"|", keep:FALSE );
  if( max_index( service_split ) < 3 ) continue;
  display_name  = service_split[1];
  service_name  = service_split[2];
  path_name     = service_split[3];

  indicators = 0;
  if( "WmiApSrvEx" >< service_name ) indicators++;
  if( "WMI Performance Adapter Extension" >< display_name )  indicators++;
  if( "ControlTrace -Embedding -k" >< path_name ) indicators++;
  if( indicators > 1 ) {
    services_report += service + '\n';
    SERVICES_VULN = TRUE;
  }
}

if( SERVICES_VULN ) {
  report  = "Trojan.Kwampirs, a backdoor Trojan that provides attackers with remote access to this computer, has been found based on the following IOCs:";
  report += '\n\nDescription|DisplayName|Name|PathName\n';
  report += services_report;
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );