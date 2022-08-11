###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_player_mult_dos_vuln_may16_win.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# VMware Player Multiple Vulnerabilities May16 (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:vmware:player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806757");
  script_version("$Revision: 12096 $");
  script_cve_id("CVE-2014-8370", "CVE-2015-1043", "CVE-2015-1044");
  script_bugtraq_id(72338, 72337, 72336);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-05-20 09:35:33 +0530 (Fri, 20 May 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("VMware Player Multiple Vulnerabilities May16 (Windows)");

  script_tag(name:"summary", value:"The host is installed with VMware Player
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An arbitrary file write issue.

  - An input validation issue in the Host Guest File System (HGFS).

  - An input validation issue in VMware Authorization process (vmware-authd).");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  attacker for for privilege escalation and to cause Denial of Service.");

  script_tag(name:"affected", value:"VMware Player 6.x prior to version 6.0.5
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to VMware Player version
  6.0.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2015-0001.html");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_mandatory_keys("VMware/Win/Installed");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!vmwareVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(vmwareVer =~ "^6\.")
{
  if(version_is_less(version:vmwareVer, test_version:"6.0.5"))
  {
    report = report_fixed_ver(installed_version:vmwareVer, fixed_version:"6.0.5");
    security_message(data:report );
    exit(0);
  }
}
