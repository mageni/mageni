###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_hadoop_password_exposure_vuln.nasl 11977 2018-10-19 07:28:56Z mmartin $
#
# Apache Hadoop Password Exposure Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.112036");
  script_version("$Revision: 11977 $");
  script_cve_id("CVE-2016-3086");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 09:28:56 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-27 20:31:53 +0530 (Tue, 27 Jun 2017)");
  script_name("Apache Hadoop Password Exposure Vulnerability");

  script_tag(name:"summary", value:"The host is installed with Apache Hadoop
  and is prone to a password exposure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The YARN NodeManager in Apache Hadoop can leak the password for credential store provider used by the NodeManager to YARN Applications.");

  script_tag(name:"impact", value:"By using the CredentialProvider feature to encrypt passwords used in
      NodeManager configs, it may be possible for any Container launched by
      that NodeManager to gain access to the encryption password. The other
      passwords themselves are not directly exposed.");

  script_tag(name:"affected", value:"All versions of Hadoop 2.6.x before 2.6.5 and 2.7.x before 2.7.3.");

  script_tag(name:"solution", value:"Upgrade to Apache Hadoop version 2.6.5 or 2.7.3 or
  later or set the permission of the jceks file appropriately to restrict access from unauthorized users.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://mail-archives.apache.org/mod_mbox/hadoop-general/201701.mbox/%3C0ed32746-5a53-9051-5877-2b1abd88beb6%40apache.org%3E");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_hadoop_detect.nasl");
  script_mandatory_keys("Apache/Hadoop/Installed");
  script_require_ports("Services/www", 50070);
  script_xref(name:"URL", value:"http://www.hadoop.apache.org");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!ver = get_app_version(cpe:CPE, port:port)){
  exit(0);
}

if(ver =~ "^(2\.6)")
{
  report = report_fixed_ver(installed_version:ver, fixed_version:"2.6.5");
  security_message(data:report, port:port);
  exit(0);
}

if(ver =~ "^(2\.7)")
{
  report = report_fixed_ver(installed_version:ver, fixed_version:"2.7.3");
  security_message(data:report, port:port);
  exit(0);
}
exit(99);
