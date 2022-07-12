###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_google_chrome_spdy_dos_vuln_lin.nasl 12014 2018-10-22 10:01:47Z mmartin $
#
# Google Chrome 'SPDY' Denial of Service vulnerability (Linux)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902358");
  script_version("$Revision: 12014 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 12:01:47 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-03-25 15:52:06 +0100 (Fri, 25 Mar 2011)");
  script_cve_id("CVE-2011-1465");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Google Chrome 'SPDY' Denial Of Service Vulnerability");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of
  service by using SPDY servers.");
  script_tag(name:"affected", value:"Google Chrome version prior to 11.0.696.14");
  script_tag(name:"insight", value:"The flaw is due to error in 'SPDY' implementation in
  'net/http/http_network_transaction.cc', which drains the bodies from SPDY
  responses.");
  script_tag(name:"solution", value:"Upgrade to Google Chrome version 11.0.696.14 or later");
  script_tag(name:"summary", value:"This host is installed with Google Chrome and is prone to Denial
  Of Service vulnerability.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://code.google.com/p/chromium/issues/detail?id=75657");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/03/dev-channel-update_17.html");
  script_xref(name:"URL", value:"http://src.chromium.org/viewvc/chrome/trunk/src/net/http/http_network_transaction.cc?r1=77893&r2=77892&pathrev=77893");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("Google-Chrome/Linux/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"11.0.696.14")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
