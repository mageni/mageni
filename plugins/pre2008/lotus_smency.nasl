# OpenVAS Vulnerability Test
# $Id: lotus_smency.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: ScanMail file check
#
# Authors:
# DokFLeed <dokfleed at dokfleed.net>
#
# Copyright:
# Copyright (C) 2004 by DokFLeed
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14312");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(11612);
  script_name("ScanMail file check");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2004 by DokFLeed");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script attempts to read sensitive files used by Trend
  ScanMail, an anti-virus protection program for Domino (formerly Lotus Notes).");

  script_tag(name:"impact", value:"An attacker, exploiting this flaw, may gain access to confidential
  data or disable the anti-virus protection.");

  script_tag(name:"solution", value:"Password protect access to these files.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

files = make_array("/smency.nsf"   , "Encyclopedia",
                   "/smconf.nsf"   , "Configuration",
                   "/smhelp.nsf"   , "Help",
                   "/smftypes.nsf" , "File Types",
                   "/smmsg.nsf"    , "Messages",
                   "/smquar.nsf"   , "Quarantine",
                   "/smtime.nsf"   , "Scheduler",
                   "/smsmvlog.nsf" , "Log",
                   "/smadmr5.nsf"  , "Admin Add-in");
report = "";
foreach path(keys(files)) {

  req = http_get(item:path, port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if(!res)
    continue;

  if("Trend ScanMail" >< res) {
    if(!report) {
      report = "The following files were found:";
    }
    report += string("\n    ", path, " - ", files[path]);
  }
}

if(report) {
  security_message(port:port, data:report);
  exit(0);
}

exit(99);