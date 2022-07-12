###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_policy_cpe_error.nasl 10530 2018-07-17 14:15:42Z asteins $
#
# CPE-based Policy Check Error
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.108291");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10530 $");
  script_name("CPE-based Policy Check Error");
  script_tag(name:"last_modification", value:"$Date: 2018-07-17 16:15:42 +0200 (Tue, 17 Jul 2018) $");
  script_tag(name:"creation_date", value:"2017-11-20 11:42:20 +0100 (Mon, 20 Nov 2017)");
  script_category(ACT_END);
  script_family("Policy");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_dependencies("Policy/gb_policy_cpe.nasl");
  script_mandatory_keys("policy/cpe/invalid_line/found");

  script_tag(name:"summary", value:"Shows all CPEs from the CPE-based Policy Check which have an invalid syntax.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

invalid_lines  = get_kb_list( "policy/cpe/invalid_list" );

if( invalid_lines ) {

  # Sort to not report changes on delta reports if just the order is different
  invalid_lines = sort( invalid_lines );

  report += 'The following invalid lines where identified within the uploaded/provided CPEs:\n\n';

  foreach error( invalid_lines ) {
    report += error + '\n';
  }
}

if( strlen( report ) > 0 ) {
  log_message( port:0, data:report );
}

exit( 0 );
