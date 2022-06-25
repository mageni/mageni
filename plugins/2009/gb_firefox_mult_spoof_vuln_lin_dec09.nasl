###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefox_mult_spoof_vuln_lin_dec09.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# Mozilla Firefox Multiple Spoofing Vulnerabilies - dec09 (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801094");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-12-17 08:14:37 +0100 (Thu, 17 Dec 2009)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_cve_id("CVE-2009-4129", "CVE-2009-4130");
  script_bugtraq_id(37230, 37232);
  script_name("Mozilla Firefox Multiple Spoofing Vulnerabilies - dec09 (Linux)");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54612");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54611");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Dec/1023287.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("Firefox/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct spoofing attacks and
  possibly launch further attacks on the system.");
  script_tag(name:"affected", value:"Mozilla Firefox version 3.0 to 3.5.5 on Linux.");
  script_tag(name:"insight", value:"- A race condition error allows attackers to produce a JavaScript message with
    a spoofed domain association by writing the message in between the document
    request and document load for a web page in a different domain.

  - Visual truncation vulnerability in the MakeScriptDialogTitle function in
    nsGlobalWindow.cpp in Mozilla Firefox allows remote attackers to spoof the
    origin domain name of a script via a long name.");
  script_tag(name:"solution", value:"Upgrade to Firefox version 3.6.3 or later.");
  script_tag(name:"summary", value:"The host is installed with Firefox browser and is prone to multiple
  spoofing vulnerabilies.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/firefox.html");
  exit(0);
}


include("version_func.inc");

ffVer = get_kb_item("Firefox/Linux/Ver");
if(!ffVer){
  exit(0);
}

if(version_in_range(version:ffVer, test_version:"3.0", test_version2:"3.5.5")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
