###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tor_dos_vuln_jul09_lin.nasl 12635 2018-12-04 08:00:20Z cfischer $
#
# Tor Denial Of Service Vulnerability - July09 (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800841");
  script_version("$Revision: 12635 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 09:00:20 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-07-17 12:47:28 +0200 (Fri, 17 Jul 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-2425");
  script_bugtraq_id(35505);
  script_name("Tor Denial Of Service Vulnerability - July09 (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35546");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51376");
  script_xref(name:"URL", value:"http://archives.seul.org/or/announce/Jun-2009/msg00000.html");
  script_xref(name:"URL", value:"http://www.torproject.org/download.html.en");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_tor_detect_lin.nasl");
  script_mandatory_keys("Tor/Linux/Ver");

  script_tag(name:"affected", value:"Tor version 0.2.x before 0.2.0.35 on Linux.");

  script_tag(name:"insight", value:"Error exists while parsing certain malformed router descriptors and can be
  exploited to crash Tor via specially crafted router descriptors.");

  script_tag(name:"solution", value:"Upgrade to version 0.2.0.35 or later");

  script_tag(name:"summary", value:"This host is installed with Tor and is prone to Denial Of Service
  vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause Denial of Service.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

torVer = get_kb_item("Tor/Linux/Ver");
if(!torVer){
  exit(0);
}

torVer = ereg_replace(pattern:"-", replace:".", string:torVer);
if(version_in_range(version:torVer, test_version:"0.2", test_version2:"0.2.0.34.alpha")){
  security_message(port:0);
  exit(0);
}
