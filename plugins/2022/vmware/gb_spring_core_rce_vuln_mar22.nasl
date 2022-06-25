# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:vmware:spring_framework_core";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113865");
  script_version("2022-03-31T08:08:49+0000");
  script_tag(name:"last_modification", value:"2022-03-31 10:53:41 +0000 (Thu, 31 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-31 07:40:33 +0000 (Thu, 31 Mar 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("VMware Spring Framework (Core) RCE Vulnerability (Spring4Shell, SpringShell) - Version Check");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_vmware_spring_core_consolidation.nasl");
  script_mandatory_keys("vmware/spring/framework/core/detected");

  script_xref(name:"URL", value:"https://www.praetorian.com/blog/spring-core-jdk9-rce/");
  script_xref(name:"URL", value:"https://blog.sonatype.com/new-0-day-spring-framework-vulnerability-confirmed");
  script_xref(name:"URL", value:"https://www.lunasec.io/docs/blog/spring-rce-vulnerabilities/");
  script_xref(name:"URL", value:"https://bugalert.org/content/notices/2022-03-30-spring.html");
  script_xref(name:"URL", value:"https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement");

  script_tag(name:"summary", value:"The VMware Spring Framework (Core component) is prone to a
  remote code execution (RCE) vulnerability dubbed 'Spring4Shell' or 'SpringShell'.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Only few details are currently available, please see the
  references for first technical analysis.");

  script_tag(name:"affected", value:"VMware Spring Framework (Core component) in all versions.");

  script_tag(name:"solution", value:"If you’re able to upgrade to Spring Framework 5.3.18 and 5.2.20, no workarounds are necessary.
  
  For older, unsupported Spring Framework versions, upgrading to Apache Tomcat 10.0.20, 9.0.62, or 8.5.78, provides adequate protection. 
  However, this should be seen as a tactical solution, and the main goal should be to upgrade to a currently supported Spring Framework version as soon as possible.

  Downgrading to Java 8 is a viable workaround, if you can neither upgrade the Spring Framework nor upgrade Apache Tomcat.

  For more information read the references.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:FALSE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

report = report_fixed_ver( installed_version:version, fixed_version:"5.2.20/5.3.18", install_path:location );
security_message( port:port, data:report );

exit( 0 );
