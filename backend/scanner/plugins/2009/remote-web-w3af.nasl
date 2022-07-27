##############################################################################
# OpenVAS Vulnerability Test
# $Id: remote-web-w3af.nasl 13985 2019-03-05 07:23:54Z cfischer $
#
# Assess web security with w3af
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80109");
  script_version("$Revision: 13985 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 08:23:54 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-10-18 22:12:25 +0200 (Sun, 18 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("w3af (NASL wrapper)");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2009 Vlatko Kosturjak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "http_login.nasl", "toolcheck.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Tools/Present/w3af");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_add_preference(name:"Profile", type:"radio", value:"fast_scan;sitemap;web_infrastructure;OWASP_TOP10;audit_high_risk;bruteforce;full_audit");
  script_add_preference(name:"Seed URL", type:"entry", value:"");

  script_tag(name:"summary", value:"This plugin uses w3af (w3af_console to be exact) to find
  web security issues.

  See the preferences section for w3af options.

  Note that the scanner is using limited set of w3af options.
  Therefore, for more complete web assessment, you should
  use standalone w3af tool for deeper/customized checks.

  Note: The plugin needs the 'w3af_console' binary found within the PATH of the user running the scanner and
  needs to be executable for this user. The existence of this binary is checked and reported separately
  within 'Availability of scanner helper tools' (OID: 1.3.6.1.4.1.25623.1.0.810000).");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("global_settings.inc"); # For report_verbosity
include("misc_func.inc");

if(!get_kb_item("Tools/Present/w3af"))
  exit(0);

cmdw3af = "w3af_console";
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

seed = script_get_preference("Seed URL");
if(seed) {
  if(ereg(pattern:"^/", string:seed)) {
    httpurl = httpurl + seed;
  } else {
    httpurl = httpurl + "/" + seed;
  }
}

useprofile = script_get_preference("Profile");
if(!useprofile) useprofile = "fast_scan";

genfilename = get_tmp_dir() + vtstrings["lowercase"] + "-w3af-" + get_host_ip() + "-" + port;
cmdfilename = genfilename + ".cmd";
repfilename = genfilename + ".rep";
httpfilename = genfilename + ".http";

cmddata = "profiles use " + useprofile + '\n';
cmddata += 'plugins\n';
# console doesn't work, so we use textFile
# termios error: (25, 'Inappropriate ioctl for device')
# cmddata += 'output console\n';
# cmddata += 'output config console\n';
cmddata += 'output textFile\n';
cmddata += 'output config textFile\n';
if(report_verbosity > 1) {
  cmddata += 'set verbose True\n';
} else {
  cmddata += 'set verbose False\n';
}
cmddata += 'set httpFileName ' + httpfilename+'\n';
cmddata += 'set fileName ' + repfilename+'\n';
cmddata += 'back\n';
cmddata += 'back\n';

cookie = get_kb_item("/tmp/http/auth/" + port);
if(cookie) {
  headersfile = genfilename + ".header";
  fwrite(data:string(cookie), file:headersfile);
  cmddata += 'http-settings\n';
  cmddata += 'set  headersFile ' + headersfile + '\n';
  cmddata += 'back\n';
} else {
  auth = get_kb_item("http/auth");
  if(auth) {
    headersfile = genfilename + ".header";
    fwrite(data:auth, file:headersfile);
    cmddata += 'http-settings\n';
    cmddata += 'set  headersFile ' + headersfile + '\n';
    cmddata += 'back\n';
  }
}

cmddata += 'target\n';
cmddata += 'set target ' + httpurl + '\n';
cmddata += 'back\n';

cmddata += 'start\n';
cmddata += 'exit\n';

function on_exit() {
  if(file_stat(cmdfilename))
    unlink(cmdfilename);
  if(file_stat(httpfilename))
    unlink(httpfilename);
  if(file_stat (repfilename))
    unlink(repfilename);
  if(headersfile && file_stat(headersfile))
    unlink(headersfile);
}

fwrite(data:cmddata, file:cmdfilename);

i = 0;
argv[i++] = cmdw3af;
argv[i++] = "-s";
argv[i++] = cmdfilename;

r = pread(cmd:cmdw3af, argv:argv, cd:TRUE);
if(!r)
  exit(0); # error

if(file_stat(repfilename)) {

  rfile = fread(repfilename);
  report = 'Here is the w3af report:\n';
  report += rfile;

  report = ereg_replace(string:report, pattern:"(Finished scanning process.)(.*)", replace:"\1" + '\n\n');

  # rhttp=fread(httpfilename);
  if('- vulnerability ]' >< report) {
    security_message(port:port, data:report);
  } else {
    log_message(port:port, data:report);
  }
} else {
  text  = 'The w3af report filename is empty. That could mean that a wrong version of w3af is used or tmp dir is not accessible.\n';
  text += 'In short: Check the installation of w3af and the scanner.';
  log_message(port:port, data:text);
}