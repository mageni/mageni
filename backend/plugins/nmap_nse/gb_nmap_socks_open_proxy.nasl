###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nmap_socks_open_proxy.nasl 11966 2018-10-18 13:56:21Z cfischer $
#
# Wrapper for Nmap Socks Open Proxy NSE script.
#
# Authors:
# NSE-Script: Joao Correa
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
  script_oid("1.3.6.1.4.1.25623.1.0.801803");
  script_version("$Revision: 11966 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 15:56:21 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-01-20 07:52:11 +0100 (Thu, 20 Jan 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Nmap NSE: Socks Open Proxy");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH");
  script_family("Nmap NSE");
  script_dependencies("nmap_nse.nasl", "socks.nasl");
  script_require_ports("Services/socks4", "Services/socks5", 1080);
  script_mandatory_keys("Tools/Present/nmap", "Tools/Launch/nmap_nse");

  script_add_preference(name:"proxy.url :", value:"", type:"entry");
  script_add_preference(name:"proxy.pattern :", value:"", type:"entry");

  script_tag(name:"summary", value:"This script attempts to check if an open socks proxy is running on
  the target.

  This is a wrapper on the Nmap Security Scanner's socks-open-proxy.nse.");

  exit(0);
}

if((! get_kb_item("Tools/Present/nmap5.21") &&
   ! get_kb_item("Tools/Present/nmap5.51")) ||
   ! get_kb_item("Tools/Launch/nmap_nse")) {
 exit(0);
}

include("http_func.inc"); # make_list_unique

i = 0;

s = get_kb_list("Services/socks4");
if(!isnull(s))
  s = make_list(s);
else
  s = make_list();

s2 = get_kb_list("Services/socks5");
if(!isnull(s2))
  s2 = make_list(s2);
else
  s2 = make_list();

ports = make_list_unique(1080, s, s2);

if( pref = script_get_preference("proxy.url :")){
  args[i++] = "proxy.url="+pref;
}

if( pref = script_get_preference("proxy.pattern :")){
  args[i++] = "proxy.pattern="+pref;
}

timing_policy = get_kb_item("Tools/nmap/timing_policy");
source_iface = get_preference("source_iface");

foreach port (ports){

  argv = make_list("nmap", "--script=socks-open-proxy.nse", "-p", port, get_host_ip());

  if(i > 0) {
    scriptArgs = "--script-args=";
    foreach arg(args) {
      scriptArgs += arg + ",";
    }
    argv = make_list(argv, scriptArgs);
  }

  if(TARGET_IS_IPV6())
    argv = make_list(argv, "-6");

  if(timing_policy =~ '^-T[0-5]$')
    argv = make_list(argv, timing_policy);

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

    if("socks-open-proxy" >< result) {
      msg = string('Result found by Nmap Security Scanner (socks-open-proxy.nse) ',
                  'http://nmap.org:\n\n', result);
      security_message(data : msg, port:port);
    }
  }
  else
  {
    msg = string('Nmap command failed entirely:\n');
    log_message(data : msg, port:port);
  }
}