###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nmap_http_iis_webdav_vuln.nasl 12115 2018-10-26 09:30:41Z cfischer $
#
# Wrapper for Nmap IIS WebDAV Vulnerability
#
# Authors:
# NSE-Script: Ron Bowes and Andrew Orr
# NASL-Wrapper: Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# NSE-Script: Copyright (c) The Nmap Security Scanner (http://nmap.org)
# NASL-Wrapper: Copyright (c) 2010 Greenbone Networks GmbH (http://www.greenbone.net)
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
  script_oid("1.3.6.1.4.1.25623.1.0.801254");
  script_version("2019-04-08T06:04:46+0000");
  script_cve_id("CVE-2009-1122", "CVE-2009-1535");
  script_tag(name:"last_modification", value:"2019-04-08 06:04:46 +0000 (Mon, 08 Apr 2019)");
  script_tag(name:"creation_date", value:"2010-08-10 12:08:05 +0200 (Tue, 10 Aug 2010)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_name("Nmap NSE: IIS WebDAV Vulnerability");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH");
  script_family("Nmap NSE");
  script_dependencies("nmap_nse.nasl", "find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_mandatory_keys("Tools/Launch/nmap_nse", "Tools/Present/nmap");

  script_add_preference(name:"Base Folder :", value:"", type:"entry");
  script_add_preference(name:"Folder db :", value:"", type:"entry");
  script_add_preference(name:"Webdav Folder :", value:"", type:"entry");
  script_add_preference(name:"http-max-cache-size :", value:"", type:"entry");
  script_add_preference(name:"pipeline :", value:"", type:"entry");

  script_tag(name:"summary", value:"This script attempts to check for IIS 5.1 and 6.0 WebDAV
  Authentication Bypass Vulnerability. The vulnerability was patched
  by Microsoft MS09-020 Security patch update.

  This is a wrapper on the Nmap Security Scanner's http-iis-webdav-vuln.nse");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");

if((! get_kb_item("Tools/Present/nmap5.21") &&
   ! get_kb_item("Tools/Present/nmap5.51")) ||
   ! get_kb_item("Tools/Launch/nmap_nse")) {
 exit(0);
}

port = get_http_port(default:80);

argv = make_list("nmap", "--script=http-iis-webdav-vuln", "-p", port, get_host_ip());

i = 0;
if( pref = script_get_preference("Base Folder :")){
  args[i++] = "basefolder="+pref;
}

if( pref = script_get_preference("Folder db :")){
  args[i++] = "folderdb="+pref;
}

if( pref = script_get_preference("Webdav Folder :")){
  args[i++] = "webdavfolder="+pref;
}

if( pref = script_get_preference("http-max-cache-size :")){
  args[i++] = "http-max-cache-size="+pref;
}

if( pref = http_get_user_agent()){
  args[i++] = "http.useragent=" + pref;
}

if( pref = script_get_preference("pipeline :")){
  args[i++] = "pipeline="+pref;
}

if(i > 0) {
  scriptArgs = "--script-args=";
  foreach arg(args) {
    scriptArgs += arg + ",";
  }
  argv = make_list(argv, scriptArgs);
}

if(TARGET_IS_IPV6())
  argv = make_list(argv, "-6");

timing_policy = get_kb_item("Tools/nmap/timing_policy");
if(timing_policy =~ '^-T[0-5]$')
  argv = make_list(argv, timing_policy);

source_iface = get_preference("source_iface");
if(source_iface =~ '^[0-9a-zA-Z:_]+$') {
  argv = make_list(argv, "-e");
  argv = make_list(argv, source_iface);
}

res = pread(cmd:"nmap", argv:argv);

if(res)
{
  if("ERROR: This web server is not supported" >< res)exit(0);

  foreach line (split(res))
  {
    result = eregmatch(string:line, pattern:"http-iis-webdav-vuln: (.*)$");
    if (result) {
      msg = string('Result found by Nmap Security Scanner(http-iis-webdav-vuln.nse) ',
                   'http://nmap.org:\n', result[1]);
      security_message(data : msg, port:port);
    }
    result = eregmatch(string:line, pattern:"^nmap: (.*)$");
    if (result) {
      msg = string('Nmap command failed with following error message:\n', line);
      log_message(data : msg, port:port);
    }
  }
}
else
{
  msg = string('Following Nmap command failed entirely:\n', args);
  log_message(data : msg, port:port);
}
