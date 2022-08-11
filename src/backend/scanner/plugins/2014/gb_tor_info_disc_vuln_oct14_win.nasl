#############################################################################/##
# OpenVAS Vulnerability Test
# $Id: gb_tor_info_disc_vuln_oct14_win.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Tor 'Relay Early' Traffic Confirmation Attack Vunerability Oct14 (Windows)
#
# Authors:
# Deepmala <kdeepmala@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:tor:tor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804933");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-5117");
  script_bugtraq_id(68968);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-10-14 09:26:32 +0530 (Tue, 14 Oct 2014)");

  script_name("Tor 'Relay Early' Traffic Confirmation Attack Vunerability oct14 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Tor browser
  and is prone to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exists due to an error
  in the handling of sequences of Relay and Relay Early commands.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to manipulate protocol headers and perform traffic confirmation attack.");

  script_tag(name:"affected", value:"Tor browser before 0.2.4.23 and 0.2.5
  before 0.2.5.6-alpha on Windows");

  script_tag(name:"solution", value:"Upgrade to version 0.2.4.23 or
  0.2.5.6-alpha or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/95053");
  script_xref(name:"URL", value:"https://blog.torproject.org/blog/tor-security-advisory-relay-early-traffic-confirmation-attack");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_tor_detect_win.nasl");
  script_mandatory_keys("Tor/Win/Ver");
  script_xref(name:"URL", value:"https://www.torproject.org");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!torVer = get_app_version(cpe:CPE)){
  exit(0);
}

if((version_is_less(version:torVer, test_version:"0.2.4.23"))||
   (version_in_range(version:torVer, test_version:"0.2.5", test_version2:"0.2.5.5")))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
