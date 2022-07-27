###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vBulletin_41875.nasl 14323 2019-03-19 13:19:09Z jschulte $
#
# vBulletin 'faq.php' Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100723");
  script_version("$Revision: 14323 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:19:09 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-07-23 13:21:58 +0200 (Fri, 23 Jul 2010)");
  script_bugtraq_id(41875);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("vBulletin 'faq.php' Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/41875");
  script_xref(name:"URL", value:"http://www.vbulletin.com/forum/showthread.php?357818-Security-Patch-Release-3.8.6-PL1");
  script_xref(name:"URL", value:"http://www.vbulletin.com/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/512575");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("vbulletin_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("vBulletin/installed");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"The vendor has released a patch to address this issue. Please see the
  references for more information.");
  script_tag(name:"summary", value:"vBulletin is prone to an information-disclosure vulnerability.

  Successful exploits can allow attackers to obtain potentially
  sensitive information which may aid in other attacks.

  vBulletin 3.8.6 is affected, prior versions may also be vulnerable.");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!dir = get_dir_from_kb(port:port, app:"vBulletin")){
   exit(0);
}

url = string(dir,"/faq.php?s=&do=search&q=database&match=all&titlesonly=0");

if(buf = http_vuln_check(port:port, url:url,pattern:"Database")) {
  if("Name:" >< buf && "Host:" >< buf && "Port:" >< buf && "Username:" >< buf && "Password:" >< buf) {
    security_message(port:port);
    exit(0);
  }
}


exit(0);

