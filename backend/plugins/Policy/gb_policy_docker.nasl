##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_policy_docker.nasl 11886 2018-10-12 13:48:53Z cfischer $
#
# Docker Compliance Check
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

include("docker_policy_tests.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140121");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11886 $");

  script_tag(name:"qod", value:"98");

  script_name("Docker Compliance Check");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gb_gather_linux_host_infos.nasl", "gb_docker_service_detection_lsc.nasl");
  script_mandatory_keys("docker/info");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:48:53 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-19 10:34:29 +0100 (Thu, 19 Jan 2017)");

  script_tag(name:"summary", value:"Runs the Docker Compliance Check.

  These tests are inspired by the CIS Docker Benchmark.");

  script_xref(name:"URL", value:"https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.6_Benchmark_v1.0.0.pdf");
  script_xref(name:"URL", value:"https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.11.0_Benchmark_v1.0.0.pdf");
  script_xref(name:"URL", value:"https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.12.0_Benchmark_v1.0.0.pdf");

  script_add_preference(name:"Perform check:", type:"checkbox", value:"no");
  script_add_preference(name:"Report passed tests:", type:"checkbox", value:"no");
  script_add_preference(name:"Report failed tests:", type:"checkbox", value:"yes");
  script_add_preference(name:"Report errors:", type:"checkbox", value:"no");
  script_add_preference(name:"Minimum docker version for test 1.1:", type:"entry", value:"1.12");
  script_add_preference(name:"Report skipped tests:", type:"checkbox", value:"no");

   foreach dt ( docker_test )
   {
     if( dt['title'] )
  script_add_preference(name:dt['title'], type:"checkbox", value:"yes");
   }

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("misc_func.inc");
include("docker.inc");
include("docker_policy.inc");

docker_test_init();

if( docker_test_is_enabled( '1.0' ) )  docker_test_1_0();
if( docker_test_is_enabled( '1.1' ) )  docker_test_1_1();
if( docker_test_is_enabled( '1.2' ) )  docker_test_1_2();
if( docker_test_is_enabled( '1.3' ) )  docker_test_1_3();
if( docker_test_is_enabled( '1.4' ) )  docker_test_1_4();
if( docker_test_is_enabled( '1.5' ) )  docker_test_1_5();
if( docker_test_is_enabled( '1.6' ) )  docker_test_1_6();
if( docker_test_is_enabled( '1.7' ) )  docker_test_1_7();
if( docker_test_is_enabled( '1.8' ) )  docker_test_1_8();
if( docker_test_is_enabled( '1.9' ) )  docker_test_1_9();
if( docker_test_is_enabled( '2.0' ) )  docker_test_2_0();
if( docker_test_is_enabled( '2.1' ) )  docker_test_2_1();
if( docker_test_is_enabled( '2.2' ) )  docker_test_2_2();
if( docker_test_is_enabled( '2.3' ) )  docker_test_2_3();
if( docker_test_is_enabled( '2.4' ) )  docker_test_2_4();
if( docker_test_is_enabled( '2.5' ) )  docker_test_2_5();
if( docker_test_is_enabled( '2.6' ) )  docker_test_2_6();
if( docker_test_is_enabled( '2.7' ) )  docker_test_2_7();
if( docker_test_is_enabled( '2.8' ) )  docker_test_2_8();
if( docker_test_is_enabled( '2.9' ) )  docker_test_2_9();
if( docker_test_is_enabled( '3.0' ) )  docker_test_3_0();
if( docker_test_is_enabled( '3.1' ) )  docker_test_3_1();
if( docker_test_is_enabled( '3.2' ) )  docker_test_3_2();
if( docker_test_is_enabled( '3.3' ) )  docker_test_3_3();
if( docker_test_is_enabled( '3.4' ) )  docker_test_3_4();
if( docker_test_is_enabled( '3.5' ) )  docker_test_3_5();
if( docker_test_is_enabled( '3.6' ) )  docker_test_3_6();
if( docker_test_is_enabled( '3.7' ) )  docker_test_3_7();
if( docker_test_is_enabled( '3.8' ) )  docker_test_3_8();
if( docker_test_is_enabled( '3.9' ) )  docker_test_3_9();
if( docker_test_is_enabled( '4.0' ) )  docker_test_4_0();
if( docker_test_is_enabled( '4.1' ) )  docker_test_4_1();
if( docker_test_is_enabled( '4.2' ) )  docker_test_4_2();
if( docker_test_is_enabled( '4.3' ) )  docker_test_4_3();
if( docker_test_is_enabled( '4.4' ) )  docker_test_4_4();
if( docker_test_is_enabled( '4.5' ) )  docker_test_4_5();
if( docker_test_is_enabled( '4.6' ) )  docker_test_4_6();
if( docker_test_is_enabled( '4.7' ) )  docker_test_4_7();
if( docker_test_is_enabled( '4.8' ) )  docker_test_4_8();
if( docker_test_is_enabled( '4.9' ) )  docker_test_4_9();
if( docker_test_is_enabled( '5.0' ) )  docker_test_5_0();
if( docker_test_is_enabled( '5.1' ) )  docker_test_5_1();
if( docker_test_is_enabled( '5.2' ) )  docker_test_5_2();
if( docker_test_is_enabled( '5.3' ) )  docker_test_5_3();
if( docker_test_is_enabled( '5.4' ) )  docker_test_5_4();
if( docker_test_is_enabled( '5.5' ) )  docker_test_5_5();
if( docker_test_is_enabled( '5.6' ) )  docker_test_5_6();
if( docker_test_is_enabled( '5.7' ) )  docker_test_5_7();
if( docker_test_is_enabled( '5.8' ) )  docker_test_5_8();

docker_test_end();

exit( 0 );

