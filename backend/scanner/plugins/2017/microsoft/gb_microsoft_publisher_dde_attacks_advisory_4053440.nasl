###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Publisher 'Dynamic Data Exchange (DDE)' Attacks Security Advisory (4053440)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812078");
  script_version("2019-05-17T13:14:58+0000");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 13:14:58 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2017-11-10 15:53:35 +0530 (Fri, 10 Nov 2017)");
  script_name("Microsoft Publisher 'Dynamic Data Exchange (DDE)' Attacks Security Advisory (4053440)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Security Advisory 4053440.");

  script_tag(name:"vuldetect", value:"Get the installed application version and
  check through the registry whether appropriate DDE features are disabled or not.");

  script_tag(name:"insight", value:"The flaw exists as the Microsoft Office provides
  several methods for transferring data between applications and the 'DDE' protocol
  is one such set of messages and guidelines. It sends messages between applications
  that share data, and uses shared memory to exchange data between applications.
  Applications can use the DDE protocol for one-time data transfers and for
  continuous exchanges in which applications send updates to one another as new
  data becomes available.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to perform code execution on the targeted device.");

  script_tag(name:"affected", value:"Microsoft Publisher 2016

  Microsoft Publisher 2013

  Microsoft Publisher 2010

  Microsoft Publisher 2007");

  script_tag(name:"solution", value:"Disable the DDE feature via the registry
  editor or user interface as given in advisory.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/4053440");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Publisher/Version");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

pubVer = get_kb_item("SMB/Office/Publisher/Version");
if(!pubVer){
  exit(0);
}

pubPath = get_kb_item("SMB/Office/Publisher/Installed/Path");
if(!pubPath){
  pubPath = "Unable to fetch the install path";
}

if(pubVer =~ "^16")
{
  offVer = "16.0";
  office = '2016';
} else if(pubVer =~ "^15")
{
  offVer = "15.0";
  office = '2013';
} else if(pubVer =~ "^14")
{
  offVer = "14.0";
  office = '2010';
} else if(pubVer =~ "^12")
{
  offVer = "12.0";
  office = '2007';
}

if(offVer =~ "^1[4-6]")
{
  keyOff = "Software\Microsoft\Office\" + offVer + "\Word\Options";
  item = "DontUpdateLinks";
} else if (offVer =~ "^12")
{
  keyOff = "Software\Microsoft\Office\" + offVer + "\Word\Options\vpref";
  item = "fNoCalclinksOnopen_90_1";
}

if(!registry_key_exists(key:keyOff, type:"HKCU")){
  exit(0);
}

ddedisableitem = registry_get_dword(key:keyOff, item:item, type:"HKCU");

##DDE disabled == 1
if(ddedisableitem == "1"){
  exit(0);
}else
{
  ##If item not present or ddedisableitem == 0, then DDE enabled
  report = report_fixed_ver(installed_version: pubVer, fixed_version: "Disable DDE", install_path:pubPath);
  security_message(data:report);
  exit(0);
}
exit(0);
