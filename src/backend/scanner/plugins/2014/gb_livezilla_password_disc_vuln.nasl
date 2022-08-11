###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_livezilla_password_disc_vuln.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# LiveZilla Password Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:livezilla:livezilla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804403");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2013-7033");
  script_bugtraq_id(64378);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-02-19 15:34:01 +0530 (Wed, 19 Feb 2014)");
  script_name("LiveZilla Password Disclosure Vulnerability");

  script_tag(name:"summary", value:"The host is installed with LiveZilla and is prone to password disclosure
  vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able
  read the password or not.");
  script_tag(name:"insight", value:"LiveZilla contains a flaw that is due to the application storing credential
  information in plaintext. This will allow an attacker to gain access to
  username and password information.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain sensitive
  information from the application, such as logged-in user credentials,
  which may aid in further attacks.");
  script_tag(name:"affected", value:"LiveZilla version 5.1.2.0");
  script_tag(name:"solution", value:"Upgrade to LiveZilla 5.1.2.1 or later.");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Dec/74");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/124444");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_livezilla_detect.nasl");
  script_mandatory_keys("LiveZilla/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://livezilla.net");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!lzPort = get_app_port(cpe:CPE)){
#  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:lzPort)){
  exit(0);
}

if( dir == "/" ) dir = "";

url = dir + "/mobile/chat.php?acid=d412e";

if(http_vuln_check(port:lzPort, url: url, check_header: TRUE,
   pattern: "loginPassword = '",
   extra_check: make_list("loginName = '", "Livezilla Mobile")))
{
  security_message(port:lzPort);
  exit(0);
}

exit(99);