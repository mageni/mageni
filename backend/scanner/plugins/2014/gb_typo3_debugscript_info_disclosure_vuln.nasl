###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typo3_debugscript_info_disclosure_vuln.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# TYPO3 Debug Script Information Disclosure Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
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

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803980");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2005-4875");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-12-17 13:20:01 +0530 (Tue, 17 Dec 2013)");
  script_name("TYPO3 Debug Script Information Disclosure Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain sensitive
environment variables information or may lead to DoS.");
  script_tag(name:"vuldetect", value:"Send a Crafted HTTP GET request and check whether it is able to get sensitive
information.");
  script_tag(name:"insight", value:"Multiple error exists in the application,

  - An error exists in debug script which executes phpinfo() function, which
makes environment variables world readable.

  - An error exists in TYPO3 Page Cache.

  - An error exists in config.baseURL, which could be used to spoof a malicious
baseURL into your TYPO3 cache.

  - An error exists in TYPO3 Install Tool, which does not generate a secure
encryptionKey

  - An error exists in showpic.php, which fails to sanatize user inputs properly.

  - An error exists in application, which does not forbidden access to
'fileadmin/_temp_/' directory");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to TYPO3 version 3.8.1 or later.");
  script_tag(name:"summary", value:"This host is installed with TYPO3 and is prone to information disclosure
vulnerability.");
  script_tag(name:"affected", value:"TYPO3 version before 3.8.1");

  script_xref(name:"URL", value:"http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-20051114-1");
  script_xref(name:"URL", value:"http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-20051114-2");
  script_xref(name:"URL", value:"http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-20051114-4");
  script_xref(name:"URL", value:"http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-20051114-5");
  script_xref(name:"URL", value:"http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-20051114-6");
  script_xref(name:"URL", value:"http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-20051114-7");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_typo3_detect.nasl");
  script_mandatory_keys("TYPO3/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!typoPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(typoLoca = get_app_location(cpe:CPE, port:typoPort))
{
  typoUrl = typoLoca + "/misc/phpcheck/index.php?arg1,arg2,arg3&p1=parameter1&p2[key]=value#link1";

  if(http_vuln_check(port: typoPort, url: typoUrl, check_header: FALSE,
     pattern: "TYPO3_HOST_ONLY", extra_check:make_list("SCRIPT_FILENAME", "<title>phpinfo\(\)</title>")))
  {
    security_message(typoPort);
    exit(0);
  }
}
