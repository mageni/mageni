# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108767");
  script_version("2020-08-12T14:39:42+0000");
  script_cve_id("CVE-2017-5753", "CVE-2017-5715", "CVE-2017-5754", "CVE-2019-1125", "CVE-2018-3639",
                "CVE-2018-3615", "CVE-2018-3620", "CVE-2018-3646", "CVE-2018-12126", "CVE-2018-12130",
                "CVE-2018-12127", "CVE-2019-11091", "CVE-2019-11135", "CVE-2018-12207");
  script_tag(name:"last_modification", value:"2020-08-13 10:32:48 +0000 (Thu, 13 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-06-02 05:50:19 +0000 (Tue, 02 Jun 2020)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:P/A:N");
  script_name("Missing Linux Kernel mitigations for hardware vulnerabilities (sysfs interface not available)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_hw_vuln_linux_kernel_mitigation_detect.nasl");
  script_mandatory_keys("ssh/hw_vulns/kernel_mitigations/sysfs_not_available");

  script_xref(name:"URL", value:"https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/index.html");

  script_tag(name:"summary", value:"The remote host is missing all known mitigation(s) on Linux Kernel
  side for the referenced hardware vulnerabilities.

  Note: The sysfs interface to read the migitation status from the Linux Kernel is not available. Based on this it is
  assumed that no Linux Kernel mitigations are available and that the host is affected by all vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks previous gathered information on the mitigation status reported
  by the Linux Kernel.");

  script_tag(name:"solution", value:"Enable the mitigation(s) in the Linux Kernel or update to a more
  recent Linux Kernel.");

  script_tag(name:"qod", value:"30"); # nb: Unreliable (sysfs interface might not be available for some reason) and none of the existing QoD types are matching here
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

if( ! get_kb_item( "ssh/hw_vulns/kernel_mitigations/sysfs_not_available" ) )
  exit( 99 );

report = get_kb_item( "ssh/hw_vulns/kernel_mitigations/sysfs_not_available/report" );
if( report ) {
  report += " If this is wrong please make the sysfs interface available for the scanning user.";
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
