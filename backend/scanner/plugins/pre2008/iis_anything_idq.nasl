###############################################################################
# OpenVAS Vulnerability Test
# $Id: iis_anything_idq.nasl 14336 2019-03-19 14:53:10Z mmartin $
#
# IIS IDA/IDQ Path Disclosure
#
# Authors:
# Filipe Custodio <filipecustodio@yahoo.com>
# Changes by rd :
# - description slightly modified to include a solution
#
# Copyright:
# Copyright (C) 2000 Filipe Custodio
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10492");
  script_version("$Revision: 14336 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:53:10 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1065);
  script_cve_id("CVE-2000-0071");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("IIS IDA/IDQ Path Disclosure");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2000 Filipe Custodio");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("IIS/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution", value:"Select 'Preferences ->Home directory ->Application',
  and check the checkbox 'Check if file exists' for the ISAPI mappings of your server.");

  script_tag(name:"summary", value:"IIS 4.0 allows a remote attacker to obtain the real pathname
  of the document root by requesting non-existent files with .ida or .idq extensions.");

  script_tag(name:"impact", value:"An attacker may use this flaw to gain more information about
  the remote host, and hence make more focused attacks.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

sig = get_http_banner(port:port);
if( ! sig || "IIS" >!< sig ) exit(0);

url = "/anything.idq";
req = http_get(item:url, port:port);
r = http_send_recv(port:port, data:req);

str = egrep(pattern:"^<HTML>", string:r) - "<HTML>";
str = tolower(str);

if(egrep(pattern:"[a-z]\:\\.*anything", string:str)) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
} else {
  url = "/anything.ida";
  req = http_get(item:url, port:port);
  r = http_send_recv(port:port, data:req);
  str = egrep(pattern:"^<HTML>", string:r) - "<HTML>";
  str = tolower(str);
  if(egrep(pattern:"[a-z]\:\\.*anything", string:str)) {
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);