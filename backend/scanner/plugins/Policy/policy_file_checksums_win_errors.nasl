###############################################################################
# OpenVAS Vulnerability Test
# $Id: policy_file_checksums_win_errors.nasl 11886 2018-10-12 13:48:53Z cfischer $
#
# List Windows File with checksum errors
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
# Thomas Rotter <thomas.rotter@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.96182");
  script_version("$Revision: 11886 $");
  script_name("Windows file Checksums: Errors");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:48:53 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-09-09 11:11:22 +0200 (Mon, 09 Sep 2013)");
  script_category(ACT_GATHER_INFO);
  script_family("Policy");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_dependencies("Policy/policy_file_checksums_win.nasl");
  script_mandatory_keys("policy/file_checksums_win/started");

  script_tag(name:"summary", value:"List Windows files with checksum errors (missing files or other errors)");

  script_tag(name:"qod", value:"98"); # direct authenticated file analysis is pretty reliable

  exit(0);
}

md5errors      = get_kb_list( "policy/file_checksums_win/md5_error_list" );
sha1errors     = get_kb_list( "policy/file_checksums_win/sha1_error_list" );
general_errors = get_kb_list( "policy/file_checksums_win/general_error_list" );
invalid_lines  = get_kb_list( "policy/file_checksums_win/invalid_list" );

if( md5errors || sha1errors ) {

  # Sort to not report changes on delta reports if just the order is different
  if( md5errors )  md5errors  = sort( md5errors );
  if( sha1errors ) sha1errors = sort( sha1errors );

  report += 'The following files are missing or showed some errors during the check:\n\n';
  report += 'Filename|Result|Errorcode;\n';

  foreach error( md5errors ) {
    report += error + '\n';
  }
  foreach error( sha1errors ) {
    report += error + '\n';
  }
  report += '\n';
}

if( general_errors ) {

  # Sort to not report changes on delta reports if just the order is different
  general_errors = sort( general_errors );

  report += 'The following errors occurred during the check:\n\n';

  foreach error( general_errors ) {
    report += error + '\n';
  }
  report += '\n';
}

if( invalid_lines ) {

  # Sort to not report changes on delta reports if just the order is different
  invalid_lines = sort( invalid_lines );

  report += 'The following invalid lines where identified within the uploaded policy file:\n\n';
  report += 'Line|Result|Errorcode;\n';

  foreach error( invalid_lines ) {
    report += error + '\n';
  }
  report += '\n';
}

if( ! get_kb_item( "policy/file_checksums_win/no_timeout" ) ) {
  report += "A timeout happened during the check. Consider raising the 'Timeout' value of the NVT " +
            "'Windows file Checksums' (OID: 1.3.6.1.4.1.25623.1.0.96180)";
}

if( strlen( report ) > 0 ) {
  log_message( port:0, data:report );
}

exit( 0 );
