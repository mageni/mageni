###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ipfire_oinkcode_param_rem_com_inj_vuln.nasl 12467 2018-11-21 14:04:59Z cfischer $
#
# IPFire 'OINKCODE' Parameter Remote Command injection Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.811728");
  script_version("$Revision: 12467 $");
  script_cve_id("CVE-2017-9757");
  script_bugtraq_id(99173);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 15:04:59 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-09-06 16:29:23 +0530 (Wed, 06 Sep 2017)");
  script_name("IPFire 'OINKCODE' Parameter Remote Command injection Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ipfire/system-release");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42149");
  script_xref(name:"URL", value:"http://www.ipfire.org/news/ipfire-2-19-core-update-112-released");

  script_tag(name:"summary", value:"This host is running IPFire and is prone to
  remote command injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as the file 'ids.cgi'
  doesn't sanitize the 'OINKCODE' parameter and input gets passed to a system
  call which call wget.");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow
  an attacker to execute arbitrary code in the context of the affected
  application. Failed exploit attempts may cause a denial-of-service condition.");

  script_tag(name:"affected", value:"IPFire versions prior to 2.19 Core Update 112");

  script_tag(name:"solution", value:"Upgrade to IPFire version 2.19 Core
  Update 112 or later.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

if(!rls = get_kb_item("ipfire/system-release")){
  exit(0);
}

if( "IPFire" >!< rls ){
  exit(0);
}

vers = eregmatch( pattern:'IPFire ([0-9.]+[^ ]*)', string:rls );
if(!vers[1]){
  exit(0);
} else {
  version = vers[1];
}

core_update = eregmatch( pattern:'core([0-9]+)', string:rls );
if(core_update[1]){
  core = core_update[1];
} else {
  core = 0;
}

firVersion = version + '.' + core;

if(version_is_less( version:firVersion, test_version:"2.19.112")){
  report = report_fixed_ver( installed_version:version + ' Core Update' + core, fixed_version:"2.19 Core Update 112");
  security_message( port:0, data:report );
}

exit(0);