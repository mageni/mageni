###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_panda_global_prot_bof_vuln.nasl 14117 2019-03-12 14:02:42Z cfischer $
#
# Panda Global Protection Heap Based Buffer Overflow Sept14
#
# Authors:
# Deepmala <kdeepmala@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:pandasecurity:panda_global_protection_2014";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804906");
  script_version("$Revision: 14117 $");
  script_cve_id("CVE-2014-5307");
  script_bugtraq_id(69293);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-09-22 16:48:04 +0530 (Mon, 22 Sep 2014)");

  script_name("Panda Global Protection Heap Based Buffer Overflow Sept14");

  script_tag(name:"summary", value:"This host is installed with Panda Global Protection
  and is prone to heap based buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exist due to improper bounds checking
  by the PavTPK.sys kernel mode driver.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause a heap-based buffer overflow by sending a specially crafted IOCTL request
  and execute arbitrary code on the system with kernel-level privileges.");

  script_tag(name:"affected", value:"Panda Global Protection 2014 7.01.01");

  script_tag(name:"solution", value:"Apply the hotfix 'hft131306s24_r1'.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/95382");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/127948/Panda-Security-2014-Privilege-Escalation.html");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Buffer overflow");
  script_dependencies("gb_panda_prdts_detect.nasl");
  script_mandatory_keys("Panda/GlobalProtection/Ver");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!version = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version:version, test_version:"7.01.01"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
