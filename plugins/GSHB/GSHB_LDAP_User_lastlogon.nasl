###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_LDAP_User_lastlogon.nasl 13769 2019-02-19 15:52:41Z cfischer $
#
# Search in LDAP the lastLogonTimestamp of Users.
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.96170");
  script_version("$Revision: 13769 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-19 16:52:41 +0100 (Tue, 19 Feb 2019) $");
  script_tag(name:"creation_date", value:"2012-08-10 09:43:28 +0200 (Fri, 10 Aug 2012)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Search in LDAP the lastLogonTimestamp of Users.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_dependencies("GSHB/GSHB_WMI_OSInfo.nasl", "toolcheck.nasl");
  script_mandatory_keys("Compliance/Launch/GSHB");

  script_add_preference(name:"Testuser Common Name", type:"entry", value:"CN");
  script_add_preference(name:"Testuser Organization Unit", type:"entry", value:"OU");

  script_tag(name:"summary", value:"This script search in LDAP the lastLogonTimestamp of Users.");

  script_tag(name:"qod_type", value:"exploit");

  exit(0);
}

include("misc_func.inc");
include("smb_nt.inc");

WindowsDomain = get_kb_item("WMI/WMI_WindowsDomain");
WindowsDomainrole = get_kb_item("WMI/WMI_WindowsDomainrole");
passwd = kb_smb_password();

CN = script_get_preference("Testuser Common Name");
OU = script_get_preference("Testuser Organization Unit");

if (OU == "OU") OU = get_kb_item("GSHB/OU");
if (CN == "CN") CN = get_kb_item("GSHB/CN");
DomFunkMod = get_kb_item("GSHB/DomFunkMod");

if(!WindowsDomainrole || WindowsDomainrole == "none"){
  set_kb_item(name:"GSHB/lastLogonTimestamp", value:"error");
  set_kb_item(name:"GSHB/lastLogonTimestamp/log", value:"It was not possible to get an Information over WMI");
  exit(0);
}

if(WindowsDomainrole < 4){
  log_message(port:0, proto: "IT-Grundschutz", data: 'The target is not an Windows Domaincontroller');
  set_kb_item(name:"GSHB/lastLogonTimestamp", value:"error");
  set_kb_item(name:"GSHB/lastLogonTimestamp/log", value:'The target is not an Windows Domaincontroller. \nIt has ' + WindowsDomainrole + ' as Windows Domainrole.\nOnly 4 and 5 are Domaincontrollers.');
  exit(0);
}

port = get_kb_item("Services/ldap");
if (! port) port = 389;
if (! get_port_state(port)){
  log_message(port:0, proto: "IT-Grundschutz", data: 'No Access to port 389!');
  set_kb_item(name:"GSHB/lastLogonTimestamp", value:"error");
  exit(0);
}

if (! get_kb_item("Tools/Present/ldapsearch")){
  set_kb_item(name:"GSHB/lastLogonTimestamp", value:"error");
  set_kb_item(name:"GSHB/lastLogonTimestamp/log", value:"Command -ldapsearch- not available to scan server (not in\nsearch path). Therefore this test was not executed.");
  exit(0);
}

if (OU == "OU" || CN == "CN" || OU == "" || CN == ""){
  set_kb_item(name:"GSHB/lastLogonTimestamp", value:"error");
  set_kb_item(name:"GSHB/lastLogonTimestamp/log", value:"Please Configure the Values -Testuser Common Name- and\n-Testuser Organization Unit- under Plugin Settings\n(NVT: Search in LDAP the lastLogonTimestamp of Users. or\nNVT: Compliance Tests)");
  exit(0);
}

CN = "CN=" + CN;
if (tolower(OU) == "users" || tolower(OU) == "user"){
  OU = "CN=" + OU;
}else{
  OU = "OU=" + OU;
}
split_dom = split(WindowsDomain, sep:'.', keep:0);
for(e=0; e<max_index(split_dom); e++){
  bind = "DC=" + split_dom[e];
  if (!bindloop) bindloop = bind;
  else bindloop = bindloop + "," + bind;
}

function argd(bind,CN,passwd)
{
  d = 0;
  argd[d++] = "ldapsearch";
  argd[d++] = "-x";
  argd[d++] = "-h";
  argd[d++] = get_host_ip();
  argd[d++] = "-b";
  argd[d++] = "CN=Partitions,CN=Configuration," + bindloop;
  argd[d++] = "-D";
  argd[d++] = CN + "," + OU +"," + bindloop;
  argd[d++] = "-w";
  argd[d++] = passwd;
  argd[d++] = "msDS-Behavior-Version";
  return(argd);
}

if (!DomFunkMod || DomFunkMod == "none" || int(DomFunkMod) < 3){

  arg = argd(bind:bind,CN:CN,passwd:passwd);
  res = pread(cmd:"ldapsearch", argv: arg, nice: 5);

  if ("ldap_bind: Invalid credentials (49)" >< res){
    log_message(port:0, proto: "IT-Grundschutz", data: 'An Error was occurred: ' + res);
    set_kb_item(name:"GSHB/lastLogonTimestamp", value:"error");
    set_kb_item(name:"GSHB/lastLogonTimestamp/log", value:res);
    exit(0);
  }
  split_res = split (res);
  for(m=0; m<max_index(split_res); m++){
    if (split_res[m] =~ "msDS-Behavior-Version: [0-9]{1}")DomFunkMod = split_res[m] - "msDS-Behavior-Version: ";
  }
  if(DomFunkMod && DomFunkMod != "none")DomFunkMod = ereg_replace(pattern:'\n',replace:'', string:DomFunkMod);
  if(DomFunkMod && DomFunkMod != "none")set_kb_item(name:"GSHB/LDAP/DomFunkMod", value:DomFunkMod);
}

function args(bind,CN,passwd)
{
  i = 0;
  argv[i++] = "ldapsearch";
  argv[i++] = "-x";
  argv[i++] = "-h";
  argv[i++] = get_host_ip();
  argv[i++] = "-b";
  argv[i++] = bindloop;
  argv[i++] = "-D";
  argv[i++] = CN + "," + OU +"," + bindloop;
  argv[i++] = "-w";
  argv[i++] = passwd;
  argv[i++] = "(&(objectCategory=person)(objectClass=user))";
  argv[i++] = "lastLogonTimestamp";
  return(argv);
}

arg = args(bind:bind,CN:CN,passwd:passwd);
res = pread(cmd:"ldapsearch", argv: arg, nice: 5);

if ("ldap_bind: Invalid credentials (49)" >< res){
  log_message(port:0, proto: "IT-Grundschutz", data: 'An Error was occurred: ' + res);
  set_kb_item(name:"GSHB/lastLogonTimestamp", value:"error");
  set_kb_item(name:"GSHB/lastLogonTimestamp/log", value:res);
  exit(0);
}

split_res = split (res, sep:'# ', keep:0);
for(i=0; i<max_index(split_res); i++){
  user = split (split_res[i], sep:',', keep:0);
  user = user[0];
  val = split(split_res[i]);
  for(a=0; a<max_index(val); a++){
    if (val[a] =~ "lastLogonTimestamp: [0-9]{1,}")TS = val[a] - "lastLogonTimestamp: ";
  }
  if (TS && TS != "none")Userlist += user + "," + ereg_replace(pattern:'\n',replace:'', string:TS) + ";";
  TS = "none";

}

if (!Userlist) result = "none";

set_kb_item(name:"GSHB/lastLogonTimestamp/Userlist", value:Userlist);

exit(0);
