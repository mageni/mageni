###############################################################################
# OpenVAS Vulnerability Test
#
# PeaZIP Remote Code Execution Vulnerability (Windows)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800593");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-07-03 15:23:01 +0200 (Fri, 03 Jul 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2261");
  script_name("PeaZIP Remote Code Execution Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://www.vulnaware.com/?p=16018");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35352/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_peazip_detect_win.nasl");
  script_mandatory_keys("PeaZIP/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to exectue arbitrary code on
  the affected system via files containing shell metacharacters and commands
  contained in a ZIP archive.");
  script_tag(name:"affected", value:"PeaZIP version 2.6.1 and prior on Windows.");
  script_tag(name:"insight", value:"The flaw is due to insufficient sanitation of input data while
  processing the names of archived files.");
  script_tag(name:"solution", value:"Update to PeaZIP version 2.6.2.");
  script_tag(name:"summary", value:"This host is installed with PeaZIP and is prone to Remote
  Code Execution vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

version = get_kb_item("PeaZIP/Win/Ver");
if(!version)
  exit(0);

if(version_is_less_equal(version:version, test_version:"2.6.1")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
