###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_microsoft_windows_dns_cache_output.nasl 10563 2018-07-22 10:40:42Z cfischer $
#
# Microsoft Windows DNS Cache Output
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.112060");
  script_version("$Revision: 10563 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-22 12:40:42 +0200 (Sun, 22 Jul 2018) $");
  script_tag(name:"creation_date", value:"2017-09-28 11:44:12 +0200 (Thu, 28 Sep 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"registry");

  script_name("Microsoft Windows DNS Cache Output");
  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("toolcheck.nasl", "smb_registry_access.nasl");
  script_family("Windows");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_access", "Tools/Present/wmi");
  script_exclude_keys("win/lsc/disable_win_cmd_exec");

  script_tag(name:"summary", value:"This plugin creates a comma-separated (CSV) output of the target's DNS cache (from the 'ipconfig /displaydns' command).

  NOTE: This plugin won't run by default and needs to be enabled separately via the script preference.");

  script_add_preference(name:"Collect and report Microsoft Windows DNS Cache", type:"checkbox", value:"no");

  exit(0);
}

include("smb_nt.inc");

# nb: We don't want to run this plugin by default
run_routine = script_get_preference( "Collect and report Microsoft Windows DNS Cache" );
if( ! run_routine ) run_routine = "no";
if( run_routine == "no" ) exit( 0 );

if( get_kb_item( "win/lsc/disable_win_cmd_exec" ) ) {
  exit( 0 );
}

username = kb_smb_login();
password = kb_smb_password();

if(!username)
  exit(0);

domain = kb_smb_domain();
if(domain)
  username = domain + "/" + username;

cmd = "ipconfig /displaydns";
exec = win_cmd_exec(cmd:cmd, password:password, username:username);
output = split(exec, keep:FALSE);

csv_list = make_list();

for(i = 0; i < max_index(output)-1; i++) {
  if("Record Name" >< output[i]) {
    found = TRUE;

    name    = eregmatch(pattern:"Record Name[\.| ]+\: (\S+)",              string:output[i]);
    type    = eregmatch(pattern:"Record Type[\.| ]+\: ([0-9]+)",           string:output[i+1]);
    ttl     = eregmatch(pattern:"Time To Live[\.| ]+\: ([0-9]+)",          string:output[i+2]);
    length  = eregmatch(pattern:"Data Length[\.| ]+\: ([0-9]+)",           string:output[i+3]);
    section = eregmatch(pattern:"Section[\.| ]+\: (\S+)",                  string:output[i+4]);
    # e.g. AAAA Record, A (Host) Record, PTR Record or similar
    record  = eregmatch(pattern:"[0-9a-zA-Z\(\) ]+ Record[\.| ]+\: (\S+)", string:output[i+5]);

    csv_list = make_list(csv_list, name[1]+","+type[1]+","+ttl[1]+","+length[1]+","+section[1]+","+record[1]);
  }
}

if(found) {
  report = 'record_name,record_type,ttl,length,section,record\n';
  csv_list = sort(csv_list);
  foreach csv_line(csv_list) {
    report += csv_line + '\n';
  }
}
else {
  # Clean-up the logs from the wmiexec.py before reporting it to the end user
  output = ereg_replace( string:exec, pattern:".*Impacket.*Core Security Technologies", replace:"" );
  output = ereg_replace( string:exec, pattern:".*SMBv.*dialect used", replace:"" );
  report = 'No output of the DNS cache could be generated. Output:\n\n' + output;
}

log_message(port:0, data:report);

exit(0);
