###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_unquoted_path_vulnerabilities_win.nasl 13783 2019-02-20 11:12:24Z cfischer $
#
# Microsoft Windows Unquoted Path Vulnerability
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
# Michael Martin  <michael.martin@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.107303");
  script_version("$Revision: 13783 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-20 12:12:24 +0100 (Wed, 20 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-03-23 08:14:54 +0100 (Fri, 23 Mar 2018)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"cvss_base", value:"9.3");
  script_name("Microsoft Windows Unquoted Path Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("smb_registry_access.nasl", "gb_wmi_access.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB_or_WMI/access_successful");
  script_cve_id("CVE-2013-1609", "CVE-2014-0759", "CVE-2014-5455", "CVE-2018-6321", "CVE-2018-6016",
                "CVE-2018-6384", "CVE-2017-14019", "CVE-2016-6803", "CVE-2017-12730", "CVE-2017-9644",
                "CVE-2017-9247", "CVE-2017-3005", "CVE-2017-5873", "CVE-2016-8769", "CVE-2016-9356",
                "CVE-2016-7165", "CVE-2012-4350", "CVE-2013-1092", "CVE-2013-2176", "CVE-2013-1610",
                "CVE-2013-2231", "CVE-2013-6182", "CVE-2013-2151", "CVE-2013-2152", "CVE-2013-5011",
                "CVE-2009-2761", "CVE-2014-4634", "CVE-2015-0884", "CVE-2015-2789", "CVE-2015-1484",
                "CVE-2015-3987", "CVE-2015-4173", "CVE-2014-9646", "CVE-2015-7866", "CVE-2015-8156",
                "CVE-2016-4158", "CVE-2016-5793", "CVE-2016-6935", "CVE-2017-1000475", "CVE-2017-14030",
                "CVE-2017-15383", "CVE-2017-3757", "CVE-2017-3756", "CVE-2017-3751", "CVE-2017-6005",
                "CVE-2017-7180", "CVE-2016-8225", "CVE-2016-8102", "CVE-2016-3161", "CVE-2016-5852",
                "CVE-2013-0513", "CVE-2018-2406", "CVE-2018-5470", "CVE-2015-8988", "CVE-2018-0594",
                "CVE-2018-0595");

  script_xref(name:"URL", value:"https://gallery.technet.microsoft.com/scriptcenter/Windows-Unquoted-Service-190f0341#content");
  script_xref(name:"URL", value:"http://www.ryanandjeffshow.com/blog/2013/04/11/powershell-fixing-unquoted-service-paths-complete/");
  script_xref(name:"URL", value:"https://www.tecklyfe.com/remediation-microsoft-windows-unquoted-service-path-enumeration-vulnerability/");
  script_xref(name:"URL", value:"https://blogs.technet.microsoft.com/srd/2018/04/04/triaging-a-dll-planting-vulnerability");

  script_tag(name:"summary", value:"The script tries to detect Windows 'Uninstall' registry entries and 'Services' using an
  unquoted path containing at least one whitespace.");

  script_tag(name:"insight", value:"If the path contains spaces and is not surrounded by quotation marks, the Windows API has to guess where to find
  the referenced program. If e.g. a service is using the following unquoted path:

  C:\Program Files\Folder\service.exe

  then a start of the service would first try to run:

  C:\Program.exe

  and if not found:

  C:\Program Files\Folder\service.exe

  afterwards. In this example the behavior allows a local attacker with low privileges and write permissions on C:\ to place a malicious Program.exe which is then
  executed on a service/host restart or during the uninstallation of a software.

  NOTE: Currently only 'Services' using an unquoted path are reported as a vulnerability. The 'Uninstall' vulnerability requires an Administrator / User
  to actively uninstall the affected software to trigger this vulnerability.");

  script_tag(name:"impact", value:"A local attacker could gain elevated privileges by inserting an executable file in the path of  the affected service or uninstall entry.");

  script_tag(name:"affected", value:"Windows software installing an 'Uninstall' registry entriy or 'Service' using an unquoted path containing at least one whitespace.");

  script_tag(name:"solution", value:"Either put the listed vulnerable paths in quotation by manually using the onboard Registry editor or contact your vendor to get an update
  for the specified software that fixes this vulnerability.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

infos = kb_smb_wmi_connectinfo();
if( ! infos ) exit( 0 );

# Only try accessing via WMI if we know it is working / possible
if( get_kb_item( "WMI/access_successful" ) ) {

  handle = wmi_connect( host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"] );

  if( handle ) {

    # nb: Make sure to update the foreach loop below if adding new fields here
    query = "SELECT DisplayName, Name, PathName FROM Win32_Service WHERE NOT PathName LIKE '%c:\\windows\\System32%' AND PathName LIKE '% %'";
    services = wmi_query( wmi_handle:handle, query:query );
    wmi_close( wmi_handle:handle );
    if( services ) {

      services_list = split( services, keep:FALSE );

      foreach service( services_list ) {

        if( service == "DisplayName|Name|PathName" )
          continue; # nb: Just ignoring the header, make sure to update this if you add additional fields to the WMI query above

        service_split = split( service, sep:"|", keep:FALSE );
        path_name     = service_split[2];

        # If the path is within quotes we know its not vulnerable...
        if( egrep( string:path_name, pattern:'^".*"' ) )
          continue;

        # Basic clean-up of parameters at the end of the path_name avoid false positives if there is only a space before the parameter
        path_name = ereg_replace( string:path_name, pattern:"\s+(/|\-|\-\-).*", replace:"" ); # TODO evaluate a regex which might catch a service using something like C:\program\myservice.exe parameter1 and similar
        if( ' ' >< path_name && ! egrep( string:path_name, pattern:'^".*"' ) ) {
          services_report += service + '\n';
          SERVICES_VULN = TRUE;
        }
      }
    }
  }
}

# Only try accessing the registry if we know it is working / possible
# nb: We don't query Win32_Product via WMI here on purpose as this is quite slow
if( get_kb_item( "SMB/registry_access" ) ) {

  # The Uninstall registry keys which might hold an "unquoted" path as well
  foreach item( make_list( "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" ) ) {

    itemList = registry_enum_keys( key:item );

    foreach key( itemList ) {
      fullKey = item + "\" + key;

      uninstallstring = registry_get_sz( key:fullKey, item:"UninstallString" );
      if( strlen( uninstallstring ) > 0 ) {

        # If the path doesn't start with something like C:\foo\uninstall.exe (e.g. MsiExec.exe /X{ or "C:\foo\uninstall) we know its not vulnerable...
        if( egrep( string:uninstallstring, pattern:"^[a-zA-Z]:\\.*" ) ) {

          # Basic clean-up of parameters at the end of the uninstallstring avoid false positives if there is only a space before the parameter
          _uninstallstring = ereg_replace( string:uninstallstring, pattern:"\s+(/|\-|\-\-).*", replace:"" ); # TODO evaluate a regex which might catch a service using something like
                                                                                                             # C:\program\myuninstall.exe parameter1 and similar

          if( ' ' >< _uninstallstring && ! egrep( string:_uninstallstring, pattern:'^".*"' ) ) {
            uninstall_report += fullKey + "|" + uninstallstring + '\n';
            UNINSTALL_VULN = TRUE;
          }
        }
      }

      quietuninstallstring = registry_get_sz( key:fullKey, item:"QuietUninstallString" );
      if( strlen( quietuninstallstring ) > 0 ) {

        # If the path doesn't start with something like C:\foo\uninstall.exe (e.g. MsiExec.exe /X{ or "C:\foo\uninstall) we know its not vulnerable...
        if( egrep( string:quietuninstallstring, pattern:"^[a-zA-Z]:\\.*" ) ) {

          # Basic clean-up of parameters at the end of the uninstallstring avoid false positives if there is only a space before the parameter
          _quietuninstallstring = ereg_replace( string:quietuninstallstring, pattern:"\s+(/|\-|\-\-).*", replace:"" ); # TODO evaluate a regex which might catch a service using something like
                                                                                                                       # C:\program\myuninstall.exe parameter1 and similar

          if( ' ' >< _quietuninstallstring && ! egrep( string:_quietuninstallstring, pattern:'^".*"' ) ) {
            uninstall_report += fullKey + "|" + quietuninstallstring + '\n';
            UNINSTALL_VULN = TRUE;
          }
        }
      }
    }
  }
}

if( SERVICES_VULN || UNINSTALL_VULN ) {

  if( UNINSTALL_VULN ) {
    report  = "The following 'Uninstall' registry entries are using an 'unquoted' path:";
    report += '\n\nKey|Value\n';
    report += uninstall_report;
    log_message( port:0, data:report ); # nb: We don't want to report a vulnerability for now as a admin would need to actively uninstall a software to trigger this vulnerability.
  }

  if( SERVICES_VULN ) {
    report  = "The following services are using an 'unquoted' service path:";
    report += '\n\nDisplayName|Name|PathName\n';
    report += services_report;
    security_message( port:0, data:report );
  }
}

exit( 0 );