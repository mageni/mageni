###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_dos_vuln_apr13_lin.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Google Chrome Denial of Service Vulnerability - April 13 (Linux)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803356");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-2632");
  script_bugtraq_id(58697);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-04-02 11:17:26 +0530 (Tue, 02 Apr 2013)");
  script_name("Google Chrome Denial of Service Vulnerability - April 13 (Linux)");
  script_xref(name:"URL", value:"http://cxsecurity.com/cveshow/CVE-2013-2632");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2013/03/dev-channel-update_18.html");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause denial-of-service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 27.0.1444.3 on Linux");
  script_tag(name:"insight", value:"User-supplied input is not properly sanitized when parsing JavaScript in
  'Google V8' JavaScript Engine.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 27.0.1444.3 or later.");
  script_tag(name:"summary", value:"The host is running Google Chrome and is prone to denial of
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

if(version_is_less(version:chromeVer, test_version:"27.0.1444.3"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
