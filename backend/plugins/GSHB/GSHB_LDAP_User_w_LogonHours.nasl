###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_LDAP_User_w_LogonHours.nasl 13769 2019-02-19 15:52:41Z cfischer $
#
# Search in LDAP, Users with conf. LogonHours
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.96055");
  script_version("$Revision: 13769 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-19 16:52:41 +0100 (Tue, 19 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-02-08 10:22:28 +0100 (Mon, 08 Feb 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"exploit");
  script_name("Search in LDAP, Users with conf. LogonHours");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_OSInfo.nasl", "toolcheck.nasl");
  script_mandatory_keys("Compliance/Launch/GSHB");

  script_add_preference(name:"Testuser Common Name", type:"entry", value:"CN");
  script_add_preference(name:"Testuser Organization Unit", type:"entry", value:"OU");

  script_tag(name:"summary", value:"This script search in LDAP, Users who have configurated
  Login Timeslots (logonHours in Windows LDAP).");

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

if(!WindowsDomainrole || WindowsDomainrole == "none"){
  set_kb_item(name:"GSHB/LDAP_LogonHours", value:"error");
  set_kb_item(name:"GSHB/LDAP_LogonHours/log", value:"It was not possible to get an Information over WMI");
  exit(0);
}

if(WindowsDomainrole < 4){
  log_message(port:0, proto: "IT-Grundschutz", data: 'The target is not an Windows Domaincontroller');
  set_kb_item(name:"GSHB/LDAP_LogonHours", value:"error");
  set_kb_item(name:"GSHB/LDAP_LogonHours/log", value:'The target is not an Windows Domaincontroller. It has ' + WindowsDomainrole + ' as Windows Domainrole. Only 4 and 5 are Domaincontrollers.');
  exit(0);
}

port = get_kb_item("Services/ldap");
if (! port) port = 389;
if (! get_port_state(port)){
  log_message(port:0, proto: "IT-Grundschutz", data: 'No Access to port 389!');
  set_kb_item(name:"GSHB/LDAP_LogonHours", value:"error");
  exit(0);
}

if (! get_kb_item("Tools/Present/ldapsearch")){
  set_kb_item(name:"GSHB/LDAP_LogonHours", value:"error");
  set_kb_item(name:"GSHB/LDAP_LogonHours/log", value:"Command -ldapsearch- not available to scan server (not in\nsearch path).\nTherefore this test was not executed.");
  exit(0);
}

if (OU == "OU" || CN == "CN" || OU == "" || CN == ""){
  set_kb_item(name:"GSHB/LDAP_LogonHours", value:"error");
  set_kb_item(name:"GSHB/LDAP_LogonHours/log", value:"Please Configure the Values -Testuser Common Name- and\n-Testuser Organization Unit- under Plugin Settings");
  exit(0);
}

CN = "CN=" + CN;
if (tolower(OU) == "users" || tolower(OU) == "user"){
  OU = "CN=" + OU;
}else{
  OU = "OU=" + OU;
}
split_dom = split(WindowsDomain, sep:'.', keep:0);

for(d=0; d<max_index(split_dom); d++){

bind = "DC=" + split_dom[d];
if (!bindloop) bindloop = bind;
else bindloop = bindloop + "," + bind;
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
  argv[i++] = "(&(objectCategory=person)(objectClass=user)(logonHours=*))";
  return(argv);
}

function bintohex(bin, start, end)
{
  hex_val = "";
  for (h = start; h <= end; h = h + 1)
  {
    myhex = hex(ord(bin[h]));
    myhex = myhex - string("0x");
    hex_val += myhex;
  }
  return (hex_val);
}

arg = args(bind:bind,CN:CN,passwd:passwd);

res = pread(cmd:"ldapsearch", argv: arg, nice: 5);

#set_kb_item(name:"GSHBTEST/arg", value:arg); #TEST
#set_kb_item(name:"GSHBTEST/res", value:res); #TEST

if ("ldap_bind: Invalid credentials (49)" >< res){

  log_message(port:0, proto: "IT-Grundschutz", data: 'An Error was occurred: ' + res);
  set_kb_item(name:"GSHB/LDAP_LogonHours", value:"error");
  exit(0);
}

split_res = split (res, sep:'#', keep:0);

for(i=1; i<max_index(split_res); i++){

  dnpatt = 'dn:(.*)';
  dn = eregmatch(string:split_res[i], pattern:dnpatt, icase:1);
  dn = split (dn[0], sep:'\n', keep:0);
  dn = ereg_replace(pattern:'dn: ', string:dn[0], replace:'');

  lhpatt = 'logonHours:(.*)';
  lh = eregmatch(string:split_res[i], pattern:lhpatt, icase:1);
  lh = split (lh[0], sep:'\n', keep:0);
  lh = ereg_replace(pattern:'logonHours:: +', string:lh[0], replace:'');

  if (lh){
    lh = base64_decode(str:lh);
    lh = bintohex(bin:lh, start:0, end:15);
    if (lh != "ffffffffffffffffffffffffffffffff")result += dn + '|' + lh + '\n';
  }

}

if (!result) result = "none";

set_kb_item(name:"GSHB/LDAP_LogonHours", value:result);

exit(0);
