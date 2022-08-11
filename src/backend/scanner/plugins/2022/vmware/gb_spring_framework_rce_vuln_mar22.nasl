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

CPE = "cpe:/a:vmware:spring_framework";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113865");
  script_version("2022-04-04T13:16:12+0000");
  script_tag(name:"last_modification", value:"2022-04-05 10:21:53 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-03-31 07:40:33 +0000 (Thu, 31 Mar 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2022-22965");

  script_name("VMware Spring Framework RCE Vulnerability (Spring4Shell, SpringShell) - Version Check");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_vmware_spring_framework_consolidation.nasl");
  script_mandatory_keys("vmware/spring/framework/detected");

  script_xref(name:"URL", value:"https://tanzu.vmware.com/security/cve-2022-22965");
  script_xref(name:"URL", value:"https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement");
  script_xref(name:"URL", value:"https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement#suggested-workarounds");
  script_xref(name:"URL", value:"https://spring.io/blog/2022/04/01/spring-framework-rce-mitigation-alternative");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/5grm3b0g6co2rcw3tov34vx8r3ws9x6y");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/k1oknlyc28x25k3tnr9chr8wc37yrxlw");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/4318xzl2f9o8j3x56gx46vlst5myroc0");
  script_xref(name:"URL", value:"https://www.praetorian.com/blog/spring-core-jdk9-rce/");
  script_xref(name:"URL", value:"https://blog.sonatype.com/new-0-day-spring-framework-vulnerability-confirmed");
  script_xref(name:"URL", value:"https://www.lunasec.io/docs/blog/spring-rce-vulnerabilities/");
  script_xref(name:"URL", value:"https://bugalert.org/content/notices/2022-03-30-spring.html");

  script_tag(name:"summary", value:"The VMware Spring Framework is prone to a remote code execution
  (RCE) vulnerability dubbed 'Spring4Shell' or 'SpringShell'.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A Spring MVC or Spring WebFlux application running on JDK 9+ may
  be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the
  application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot
  executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the
  vulnerability is more general, and there may be other ways to exploit it.");

  script_tag(name:"affected", value:"VMware Spring Framework version 5.2.19 and prior and version
  5.3.x through 5.3.17.

  The following are the requirements for an environment to be affected to this specific
  vulnerability:

  - Running on JDK 9 or higher

  - Apache Tomcat as the Servlet container

  - Packaged as a traditional WAR and deployed in a standalone Tomcat instance. Typical Spring Boot
  deployments using an embedded Servlet container or reactive web server are not impacted.

  - spring-webmvc or spring-webflux dependency

  - an affected version of the Spring Framework");

  script_tag(name:"solution", value:"Update to version 5.2.20, 5.3.18 or later.

  Possible mitigations without doing an update:

  - Upgrading Tomcat (10.0.20, 9.0.62 or 8.5.78 hardened the class loader to provide a mitigation)

  - Downgrading to Java 8

  - Disallowed Fields

  Please see the references for more information on these mitigation possibilities.");

  script_tag(name:"qod_type", value:"executable_version_unreliable"); # nb: Only affected when running on Tomcat
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"5.2.20" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"5.2.20", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"5.3.0", test_version2:"5.3.17" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"5.3.18", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
