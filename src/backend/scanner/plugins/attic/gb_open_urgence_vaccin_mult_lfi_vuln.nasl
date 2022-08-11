##############################################################################
# OpenVAS Vulnerability Test
#
# Openurgence Vaccin Multiple File Inclusion Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800764");
  script_version("2020-04-02T11:36:28+0000");
  script_tag(name:"last_modification", value:"2020-04-03 10:09:42 +0000 (Fri, 03 Apr 2020)");
  script_tag(name:"creation_date", value:"2010-05-05 15:59:12 +0200 (Wed, 05 May 2010)");
  script_cve_id("CVE-2010-1466", "CVE-2010-1467");
  script_bugtraq_id(39412);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Openurgence Vaccin Multiple File Inclusion Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");

  script_tag(name:"insight", value:"Input passed to the parameter 'path_om' in various files and
  to the parameter 'dsn[phptype]' in 'scr/soustab.php' are not properly verified
  before being used to include files.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running Openurgence Vaccin and is prone multiple
  file inclusion vulnerabilities.

  This NVT has been replaced by NVT 'openUrgence Vaccin Multiple Remote File Include Vulnerabilities'
  (OID: 1.3.6.1.4.1.25623.1.0.100627).");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain
  sensitive information or compromise the application and the underlying system.");

  script_tag(name:"affected", value:"Openurgence Vaccin version 1.03");

  script_tag(name:"deprecated", value:TRUE);

  script_xref(name:"URL", value:"http://secunia.com/advisories/39400");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/57815");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/12193");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

exit(66);
