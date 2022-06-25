###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_qemu_vnc_dos_vuln_lin.nasl 12690 2018-12-06 14:56:20Z cfischer $
#
# QEMU VNC Server Denial of Service Vulnerability (Linux)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

CPE = 'cpe:/a:qemu:qemu';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900970");
  script_version("$Revision: 12690 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-06 15:56:20 +0100 (Thu, 06 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-10-31 09:54:01 +0100 (Sat, 31 Oct 2009)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3616");
  script_bugtraq_id(36716);
  script_name("QEMU VNC Server Denial of Service Vulnerability (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_qemu_detect_lin.nasl");
  script_mandatory_keys("QEMU/Lin/Ver");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=505641");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/10/16/8");
  script_xref(name:"URL", value:"http://git.savannah.gnu.org/cgit/qemu.git/commit/?id=753b405331");
  script_xref(name:"URL", value:"http://git.savannah.gnu.org/cgit/qemu.git/commit/?id=198a0039c5");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker cause memory or CPU consumption,
  resulting in Denial of Service condition.");

  script_tag(name:"affected", value:"QEMU version 0.10.6 and prior on Linux.");

  script_tag(name:"insight", value:"Multiple use-after-free errors occur in 'vnc.c' in VNC server while processing
  malicious 'SetEncodings' messages sent via VNC client.");

  script_tag(name:"summary", value:"This host is running QEMU and is prone to Denial of Service
  vulnerability.");

  script_tag(name:"solution", value:"Apply the available patches from the referenced repositories.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!ver = get_app_version(cpe:CPE)) exit(0);

if(version_is_less_equal(version:ver, test_version:"0.10.6")){
  report = report_fixed_ver(installed_version:ver, fixed_version:"0.11.0");
  security_message(data:report);
  exit(0);
}

exit(99);