###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_sim_unauth_access_vuln_win.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# HP Systems Insight Manager Unauthorized Access Vulnerability (Windows)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800033");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-10-21 16:25:40 +0200 (Tue, 21 Oct 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2008-4412");
  script_bugtraq_id(31777);
  script_name("HP Systems Insight Manager Unauthorized Access Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"http://secunia.com/advisories/32287/");
  script_xref(name:"URL", value:"http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01571962");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to gain unauthorized
  access to the data.");

  script_tag(name:"affected", value:"HP SIM prior to 5.2 with Update 2 (C.05.02.02.00) on Windows");

  script_tag(name:"insight", value:"The flaw is due to an error in the application which allows
  unauthorized access to certain data.");

  script_tag(name:"solution", value:"Update to HP SIM version 5.2 with Update 2 (C.05.02.02.00).");

  script_tag(name:"summary", value:"This host is running HP Systems Insight Manager (SIM) and is prone
  to security bypass vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");

key = "SOFTWARE\Hewlett-Packard\Systems Insight Manager\Settings";
if(!registry_key_exists(key:key)){
  exit(0);
}

simVer = registry_get_sz(item:"Version", key:key);
if(!simVer){
  exit(0);
}

if(version_is_less(version:simVer, test_version:"C.05.02.02.00")){
  report = report_fixed_ver(installed_version:simVer, fixed_version:"C.05.02.02.00");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);