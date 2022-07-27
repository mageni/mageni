###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nmap_pop3_brute.nasl 12115 2018-10-26 09:30:41Z cfischer $
#
# Wrapper for Nmap POP3 Brute NSE script.
#
# Authors:
# NSE-Script: Philip Pickering <pgpickering@gmail.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801602");
  script_version("$Revision: 12115 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 11:30:41 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2010-10-08 10:33:58 +0200 (Fri, 08 Oct 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Nmap NSE: POP3 Brute");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH");
  script_family("Nmap NSE");
  script_dependencies("find_service2.nasl", "nmap_nse.nasl");
  script_require_ports("Services/pop3", 110);
  script_mandatory_keys("Tools/Present/nmap", "Tools/Launch/nmap_nse");

  script_add_preference(name:"pop3loginmethod :", value:"", type:"entry");
  script_add_preference(name:"userdb :", value:"", type:"entry");
  script_add_preference(name:"passdb :", value:"", type:"entry");
  script_add_preference(name:"unpwdb.passlimit :", value:"", type:"entry");
  script_add_preference(name:"unpwdb.timelimit :", value:"", type:"entry");
  script_add_preference(name:"unpwdb.userlimit :", value:"", type:"entry");

  script_tag(name:"summary", value:"This script attempts to get POP3 account login credentials by guessing
  usernames and passwords.

  This is a wrapper on the Nmap Security Scanner's pop3-brute.nse.");

  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if((! get_kb_item("Tools/Present/nmap5.21") &&
   ! get_kb_item("Tools/Present/nmap5.51")) ||
   ! get_kb_item("Tools/Launch/nmap_nse")) {
 exit(0);
}

include("pop3_func.inc");

i = 0;
if( pref = script_get_preference("pop3loginmethod :")){
  args[i++] = "pop3loginmethod=" + pref;
}

if( pref = script_get_preference("userdb :")){
  args[i++] = "userdb=" + pref;
}

if( pref = script_get_preference("passdb :")){
  args[i++] = "passdb=" + pref;
}

if( pref = script_get_preference("unpwdb.passlimit :")){
  args[i++] = "unpwdb.passlimit=" + pref;
}

if( pref = script_get_preference("unpwdb.timelimit :")){
  args[i++] = "unpwdb.timelimit=" + pref;
}

if( pref = script_get_preference("unpwdb.userlimit :")){
  args[i++] = "unpwdb.userlimit=" + pref;
}

port = get_pop3_port(default:110);

argv = make_list("nmap", "--script=pop3-brute.nse", "-p", port, get_host_ip());

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

  if("pop3-brute" >< result) {
    msg = string('Result found by Nmap Security Scanner (pop3-brute.nse) ',
                'http://nmap.org:\n\n', result);
    security_message(data : msg, port:port);
  }
}
else
{
  msg = string('Nmap command failed entirely:\n');
  log_message(data : msg, port:port);
}
