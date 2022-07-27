###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_database_n_appln_server_mult_unspecified_vuln.nasl 12875 2018-12-21 15:01:59Z cfischer $
#
# Oracle Database Server and Application Server Multiple Unspecified Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802526");
  script_version("$Revision: 12875 $");
  script_cve_id("CVE-2006-0282", "CVE-2006-0283", "CVE-2006-0285", "CVE-2006-0286",
                "CVE-2006-0287", "CVE-2006-0290", "CVE-2006-0291");
  script_bugtraq_id(16287);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-12-21 16:01:59 +0100 (Fri, 21 Dec 2018) $");
  script_tag(name:"creation_date", value:"2011-12-07 12:33:26 +0530 (Wed, 07 Dec 2011)");
  script_name("Oracle Database Server and Application Server Multiple Unspecified Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_require_ports("Services/www", 7777, "Services/oracle_tnslsnr", 1521);
  script_dependencies("oracle_tnslsnr_version.nasl", "http_version.nasl");

  script_xref(name:"URL", value:"http://secunia.com/advisories/18493");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/545804");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1015499");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/24321");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/whatsnew/index.html");

  script_tag(name:"impact", value:"An unspecified impact and attack vectors.");

  script_tag(name:"affected", value:"Oracle Database server versions 8.1.7.4, 9.0.1.5, 9.2.0.6, 10.1.0.3, 9.2.0.7,
  10.1.0.5, 10.2.0.1, 9.0.1.5 FIPS, 10.1.0.4 and 10.1.0.4.2

  Oracle Application server versions 1.0.2.2, 9.0.4.2, 10.1.2.0.2, 10.1.2.1 and 10.1.3.0.0");

  script_tag(name:"insight", value:"The flaws are due to unspecified errors in the multiple components.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"summary", value:"This host is running Oracle database or application server and
  is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2006-082403.html");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

report = 'NOTE : Ignore this warning, if above mentioned patch is already applied.\n';

## Oracle Database Server ##

dbPorts = get_kb_list("Services/oracle_tnslsnr");
if(!dbPorts) dbPorts = make_list(1521);

foreach dbPort ( dbPorts ) {

  dbVer = get_kb_item("oracle_tnslsnr/" + dbPort + "/version");
  if(dbVer)
  {
    dbVer = eregmatch(pattern:"Version ([0-9.]+)", string:dbVer);
    if(dbVer[1])
    {
      if(version_is_equal(version:dbVer[1], test_version:"10.2.0.0") ||
         version_in_range(version:dbVer[1], test_version:"9.0.1", test_version2:"9.0.1.4") ||
         version_in_range(version:dbVer[1], test_version:"8.1.0", test_version2:"8.1.7.3") ||
         version_in_range(version:dbVer[1], test_version:"9.2.0", test_version2:"9.2.0.6") ||
         version_in_range(version:dbVer[1], test_version:"10.1.0", test_version2:"10.1.0.4.1"))
      {
        security_message(port:dbPort);
        continue;
      }

      if(version_is_equal(version:dbVer[1], test_version:"8.1.7.4") ||
         version_is_equal(version:dbVer[1], test_version:"9.0.1.5") ||
         version_is_equal(version:dbVer[1], test_version:"9.2.0.7") ||
         version_is_equal(version:dbVer[1], test_version:"10.1.0.5") ||
         version_is_equal(version:dbVer[1], test_version:"10.2.0.1") ||
         version_is_equal(version:dbVer[1], test_version:"10.1.0.4.2")){
          security_message(data:report, port:dbPort);
      }
    }
  }
}

if(http_is_cgi_scan_disabled()) exit(0);

## Oracle Application Server ##

appPort = get_http_port(default:7777);

banner = get_http_banner(port:appPort);

if(banner && "Oracle-Application-Server" >< banner)
{
  appVer = eregmatch(pattern:"Oracle-Application-Server-[0-9a-zA-Z]+?/([0-9.]+)",
                                             string:banner);
  if(!appVer[1]){
    exit(0);
  }

  if(version_is_less(version:appVer[1], test_version:"1.0.2.1") ||
     version_in_range(version:appVer[1], test_version:"9.0", test_version2:"9.0.4.1") ||
     version_in_range(version:appVer[1], test_version:"10.1.2.0", test_version2:"10.1.3.0"))
  {
    security_message(port:appPort);
    exit(0);
  }

  if(version_is_equal(version:appVer[1], test_version:"9.0.4.2") ||
     version_is_equal(version:appVer[1], test_version:"1.0.2.2") ||
     version_is_equal(version:appVer[1], test_version:"10.1.2.1")){
    security_message(data:report, port:appPort);
    exit(0);
  }
}

exit(99);