###############################################################################
# OpenVAS Vulnerability Test
#
# Cybozu Garoon Multiple Vulnerabilities - Aug16
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.1071655555");
  script_version("2020-04-02T11:36:28+0000");
  script_tag(name:"last_modification", value:"2020-04-03 10:09:42 +0000 (Fri, 03 Apr 2020)");
  script_tag(name:"creation_date", value:"2017-05-11 11:54:29 +0200 (Thu, 11 May 2017)");
  script_cve_id("CVE-2016-1213", "CVE-2016-1214", "CVE-2016-1215", "CVE-2016-1216", "CVE-2016-1217",
                "CVE-2016-1218", "CVE-2016-1219", "CVE-2016-1220");
  script_bugtraq_id(92596, 92598, 92599, 92600, 92601);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Cybozu Garoon Multiple Vulnerabilities - Aug16");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");


  script_tag(name:"summary", value:"This host is installed with Cybozu Garoon
  and is prone to multiple vulnerabilities.

  NOTE: This VT has been replaced by 'Cybozu Garoon Multiple Vulnerabilities - Aug16' (OID: 1.3.6.1.4.1.25623.1.0.107165)
  due to an erroneous OID.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to do redirection, XSS, authentication bypass, SQL injection and denial-of-services attacks.");

  script_tag(name:"affected", value:"Cybozu Garoon before version 4.2.2.");

  script_tag(name:"solution", value:"Update to Cybozu Garoon 4.2.2 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
