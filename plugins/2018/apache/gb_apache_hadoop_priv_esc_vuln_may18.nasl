###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Hadoop Privilege Escalation Vulnerability May18
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apache:hadoop";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813367");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2016-6811");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-05-17 12:45:23 +0530 (Thu, 17 May 2018)");
  script_name("Apache Hadoop Privilege Escalation Vulnerability May18");

  script_tag(name:"summary", value:"The host is installed with Apache Hadoop
  and is prone to privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to privilege escalation
  error while escalating to yarn user.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker who can escalate to yarn user to possibly run arbitrary commands
  as root user.");

  ## Mitigation available for affected versions
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"affected", value:"Apache Hadoop versions 2.2.0 to 2.7.3");

  script_tag(name:"solution", value:"Upgrade to Apache Hadoop version 2.7.4 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/9ba3c12bbdfd5b2cae60909e48f92608e00c8d99196390b8cfeca307@%3Cgeneral.hadoop.apache.org%3E");
  script_xref(name:"URL", value:"http://www.hadoop.apache.org");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_hadoop_detect.nasl");
  script_mandatory_keys("Apache/Hadoop/Installed");
  script_require_ports("Services/www", 50070);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!hadoopPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:hadoopPort, exit_no_version:TRUE)) exit(0);
hadoopVer = infos['version'];
hadoopPath = infos['location'];

if(version_in_range(version:hadoopVer, test_version:"2.2.0", test_version2: "2.9.3"))
{
  report = report_fixed_ver(installed_version:hadoopVer, fixed_version:"2.7.4", install_path:hadoopPath);
  security_message(data:report, port:hadoopPort);
  exit(0);
}
exit(0);
