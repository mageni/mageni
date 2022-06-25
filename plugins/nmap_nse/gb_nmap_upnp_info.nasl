###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nmap_upnp_info.nasl 12115 2018-10-26 09:30:41Z cfischer $
#
# Wrapper for Nmap UPnP Info NSE script.
#
# Authors:
# NSE-Script: Thomas Buchanan
# NASL-Wrapper: Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# NSE-Script: The Nmap Security Scanner (http://nmap.org)
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
  script_oid("1.3.6.1.4.1.25623.1.0.801699");
  script_version("2019-04-08T06:04:46+0000");
  script_tag(name:"last_modification", value:"2019-04-08 06:04:46 +0000 (Mon, 08 Apr 2019)");
  script_tag(name:"creation_date", value:"2011-01-10 13:49:23 +0100 (Mon, 10 Jan 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Nmap NSE: UPnP Info");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH");
  script_family("Nmap NSE");
  script_dependencies("nmap_nse.nasl", "gb_upnp_detect.nasl");
  script_require_udp_ports("Services/udp/upnp", 1900);
  script_mandatory_keys("Tools/Present/nmap5.21", "Tools/Launch/nmap_nse");

  script_add_preference(name:"upnp-info.override :", value:"", type:"entry");
  script_add_preference(name:"max-newtargets :", value:"", type:"entry");
  script_add_preference(name:"newtargets :", value:"", type:"entry");
  script_add_preference(name:"http-max-cache-size :", value:"", type:"entry");
  script_add_preference(name:"http.pipeline :", value:"", type:"entry");

  script_tag(name:"summary", value:"This script attempts to extract system information from the UPnP
  service.

  This is a wrapper on the Nmap Security Scanner's upnp-info.nse.");

  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");

if(! get_kb_item("Tools/Present/nmap5.21") ||
   ! get_kb_item("Tools/Launch/nmap_nse")) {
 exit(0);
}

i = 0;
if( pref = script_get_preference("upnp-info.override :")){
  args[i++] = "upnp-info.override=" + pref;
}

if( pref = script_get_preference("max-newtargets :")){
  args[i++] = "max-newtargets=" + pref;
}

if( pref = script_get_preference("newtargets :")){
  args[i++] = "newtargets=" + pref;
}

if( pref = script_get_preference("http-max-cache-size :")){
  args[i++] = "http-max-cache-size=" + pref;
}

if( pref = http_get_user_agent()){
  args[i++] = "http.useragent=" + pref;
}

if( pref = script_get_preference("http.pipeline :")){
  args[i++] = "http.pipeline=" + pref;
}

port = get_kb_item("Services/udp/upnp");
if(!port) port = 1900;
if(!get_udp_port_state(port)) exit(0);

argv = make_list("nmap", "-sU", "--script=upnp-info.nse", "-p", port, get_host_ip());

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
  foreach line (split(res))
  {
    if(ereg(pattern:"^\|",string:line)) {
      result +=  substr(chomp(line),2) + '\n';
    }

    error = eregmatch(string:line, pattern:"^nmap: (.*)$");
    if (error) {
      msg = string('Nmap command failed with following error message:\n', line);
      log_message(data : msg, port:port);
    }
  }

  if("upnp-info" >< result) {
    msg = string('Result found by Nmap Security Scanner (upnp-info.nse) ',
                'http://nmap.org:\n\n', result);
    security_message(data : msg, port:port);
  }
}
else
{
  msg = string('Nmap command failed entirely:\n');
  log_message(data : msg, port:port);
}
