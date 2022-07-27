###############################################################################
# OpenVAS Vulnerability Test
#
# Jenkins CSRF And Code Execution Vulnerabilities Aug16
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809025");
  script_version("2020-04-02T11:36:28+0000");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-04-03 10:09:42 +0000 (Fri, 03 Apr 2020)");
  script_tag(name:"creation_date", value:"2016-08-31 12:50:25 +0530 (Wed, 31 Aug 2016)");

  script_name("Jenkins CSRF And Code Execution Vulnerabilities - Feb17");

  script_tag(name:"summary", value:"This host is installed with Jenkins and is
  is prone to cross-site request forgery and code execution vulnerabilities.

  This VT has been replaced by VTs 'Jenkins Multiple Vulnerabilities - Feb17 (Linux)'
  (OID: 1.3.6.1.4.1.25623.1.0.108095) and 'Jenkins Multiple Vulnerabilities - Feb17 (Windows)'
  (OID: 1.3.6.1.4.1.25623.1.0.108096).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to an improper session
  management for most request.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to hijack the authentication of users for most request and to
  change specific settings or even execute code on os.");

  script_tag(name:"affected", value:"Jenkins version 1.626.");

  script_tag(name:"solution", value:"Updates are available to fix this issue.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37999");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");

  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2017-02-01/");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
