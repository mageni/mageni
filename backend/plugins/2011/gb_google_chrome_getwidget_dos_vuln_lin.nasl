###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_getwidget_dos_vuln_lin.nasl 12010 2018-10-22 08:23:57Z mmartin $
#
# Google Chrome 'GetWidget' methods DoS Vulnerability (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802127");
  script_version("$Revision: 12010 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 10:23:57 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-07-22 12:16:19 +0200 (Fri, 22 Jul 2011)");
  script_cve_id("CVE-2011-2761");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Google Chrome 'GetWidget' methods DoS Vulnerability (Linux)");
  script_xref(name:"URL", value:"http://codereview.chromium.org/7189019");
  script_xref(name:"URL", value:"http://code.google.com/p/chromium/issues/detail?id=86119");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/06/dev-channel-update_16.html");

  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow the attackers to cause denial-of-service
  via a crafted web site, related to GetWidget methods.");
  script_tag(name:"affected", value:"Google Chrome version 14.0.792.0");
  script_tag(name:"insight", value:"The flaw is due to error while handling a reload of a page generated
  in response to a POST which allows remote attackers to cause a denial of
  service.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 14.0.794.0 or later.");
  script_tag(name:"summary", value:"The host is installed Google Chrome and is prone to denial of
  service vulnerability.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("Google-Chrome/Linux/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_equal(version:chromeVer, test_version:"14.0.792.0")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
