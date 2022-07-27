##############################################################################
# OpenVAS Vulnerability Test
# $Id: remote-web-wapiti.nasl 13985 2019-03-05 07:23:54Z cfischer $
#
# Assess web security with wapiti
#
# Authors:
# Vlatko Kosturjak <kost@linux.hr>
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
  script_oid("1.3.6.1.4.1.25623.1.0.80110");
  script_version("$Revision: 13985 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 08:23:54 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-03-24 21:54:49 +0100 (Wed, 24 Mar 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("wapiti (NASL wrapper)");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2010 Vlatko Kosturjak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "toolcheck.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Tools/Present/wapiti");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_add_preference(name:"Nice", type:"entry", value:"");

  script_tag(name:"summary", value:"This plugin uses wapiti to find
  web security issues.

  Make sure to have wapiti 2.x as wapiti 1.x is not supported.

  See the preferences section for wapiti options.

  Note that the scanner is using limited set of wapiti options. Therefore, for more complete web
  assessment, you should use standalone wapiti tool for deeper/customized checks.

  Note: The plugin needs the 'wapiti' binary found within the PATH of the user running the scanner and
  needs to be executable for this user. The existence of this binary is checked and reported separately
  within 'Availability of scanner helper tools' (OID: 1.3.6.1.4.1.25623.1.0.810000).");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("global_settings.inc"); # For report_verbosity
include("misc_func.inc");

if(!get_kb_item("Tools/Present/wapiti"))
  exit(0);

cmdext = "wapiti";
vtstrings = get_vt_strings();

port = get_http_port(default:80);

encaps = get_port_transport(port);
if(encaps > ENCAPS_IP)
  httprefix = "https://";
else
  httprefix = "http://";

httpver = get_kb_item("http/" + port);
if(httpver == "11")
  httparg = get_host_name();
else
  httparg = get_host_ip();

httpurl = httprefix + httparg + ":" + port;

genfilename = get_tmp_dir() + vtstrings["lowercase"] + "-wapiti-" + get_host_ip() + "-" + port;
repfilename = genfilename + ".txt";

function on_exit() {
  if(file_stat(repfilename))
    unlink(repfilename);
}

nice = script_get_preference("Nice");

i = 0;
argv[i++] = cmdext;
argv[i++] = httpurl; # URL to scan (must be first!)

# options
if(report_verbosity > 1) {
  argv[i++] = "-v";
  argv[i++] = "1";
} else {
  argv[i++] = "-v";
  argv[i++] = "0";
}

if(nice && nice > 0) {
  argv[i++] = "-n";
  argv[i++] = nice;
}

argv[i++] = "-f";
argv[i++] = "txt";

argv[i++] = "-o";
argv[i++] = repfilename;

r = pread(cmd:cmdext, argv:argv, cd:TRUE);
if(!r)
  exit(0); # error

if(file_stat(repfilename)) {

  rfile = fread(repfilename);
  report='';
  if(report_verbosity > 1) {
    report += 'Here is the wapiti output:\n';
    report += r;
  }
  report += 'Here is the wapiti report:\n';
  report += rfile;
  report += '\n--- End of report ---';

  # https://github.com/IFGHou/wapiti/blob/91242a8ad293a8ee54ab6e62732ff4b9d770772c/wapitiCore/language/vulnerability.py#L72
  if(report =~ "(SQL Injection|File Handling|Cross Site Scripting|CRLF Injection|Commands execution|Htaccess Bypass|Backup file|Potentially dangerous file)") {
    security_message(port:port, data:report);
  } else {
    log_message(port:port, data:report);
  }
} else {
  text  = 'The wapiti report filename is empty. That could mean that a wrong version of wapiti is used or tmp dir is not accessible. ';
  text += 'Make sure to have wapiti 2.x as wapiti 1.x is not supported.\n';
  text += 'In short: Check the installation of wapiti and the scanner.';
  log_message(port:port, data:text);
}