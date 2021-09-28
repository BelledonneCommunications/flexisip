// Copyright (c) 2005-2014 Code Synthesis Tools CC
//
// This program was generated by CodeSynthesis XSD, an XML Schema to
// C++ data binding compiler.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
//
// In addition, as a special exception, Code Synthesis Tools CC gives
// permission to link this program with the Xerces-C++ library (or with
// modified versions of Xerces-C++ that use the same license as Xerces-C++),
// and distribute linked combinations including the two. You must obey
// the GNU General Public License version 2 in all respects for all of
// the code used other than Xerces-C++. If you modify this copy of the
// program, you may extend this exception to your version of the program,
// but you are not obligated to do so. If you do not wish to do so, delete
// this exception statement from your version.
//
// Furthermore, Code Synthesis Tools CC makes a special exception for
// the Free/Libre and Open Source Software (FLOSS) which is described
// in the accompanying FLOSSE file.
//

// Begin prologue.
//
#if __clang__ || __GNUC__ >= 4
	#pragma GCC diagnostic push
	#pragma GCC diagnostic ignored "-Wfloat-equal"
	#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
#ifndef __ANDROID__
	#pragma GCC diagnostic ignored "-Wsuggest-override"
#endif
#endif
//
// End prologue.

#include <xsd/cxx/pre.hxx>

#include "xml.hh"

namespace flexisip
{
  namespace Xsd
  {
    namespace Namespace
    {
      // Lang
      //

      Lang::
      Lang (const char* s)
      : ::flexisip::Xsd::XmlSchema::String (s)
      {
      }

      Lang::
      Lang (const ::std::string& s)
      : ::flexisip::Xsd::XmlSchema::String (s)
      {
      }

      Lang::
      Lang (const Lang& o,
            ::flexisip::Xsd::XmlSchema::Flags f,
            ::flexisip::Xsd::XmlSchema::Container* c)
      : ::flexisip::Xsd::XmlSchema::String (o, f, c)
      {
      }

      // Space
      // 

      Space::
      Space (Value v)
      : ::flexisip::Xsd::XmlSchema::Ncname (_xsd_Space_literals_[v])
      {
      }

      Space::
      Space (const char* v)
      : ::flexisip::Xsd::XmlSchema::Ncname (v)
      {
      }

      Space::
      Space (const ::std::string& v)
      : ::flexisip::Xsd::XmlSchema::Ncname (v)
      {
      }

      Space::
      Space (const ::flexisip::Xsd::XmlSchema::Ncname& v)
      : ::flexisip::Xsd::XmlSchema::Ncname (v)
      {
      }

      Space::
      Space (const Space& v,
             ::flexisip::Xsd::XmlSchema::Flags f,
             ::flexisip::Xsd::XmlSchema::Container* c)
      : ::flexisip::Xsd::XmlSchema::Ncname (v, f, c)
      {
      }

      Space& Space::
      operator= (Value v)
      {
        static_cast< ::flexisip::Xsd::XmlSchema::Ncname& > (*this) = 
        ::flexisip::Xsd::XmlSchema::Ncname (_xsd_Space_literals_[v]);

        return *this;
      }


      // Lang_member
      // 

      Lang_member::
      Lang_member (Value v)
      : ::flexisip::Xsd::XmlSchema::String (_xsd_Lang_member_literals_[v])
      {
      }

      Lang_member::
      Lang_member (const char* v)
      : ::flexisip::Xsd::XmlSchema::String (v)
      {
      }

      Lang_member::
      Lang_member (const ::std::string& v)
      : ::flexisip::Xsd::XmlSchema::String (v)
      {
      }

      Lang_member::
      Lang_member (const ::flexisip::Xsd::XmlSchema::String& v)
      : ::flexisip::Xsd::XmlSchema::String (v)
      {
      }

      Lang_member::
      Lang_member (const Lang_member& v,
                   ::flexisip::Xsd::XmlSchema::Flags f,
                   ::flexisip::Xsd::XmlSchema::Container* c)
      : ::flexisip::Xsd::XmlSchema::String (v, f, c)
      {
      }

      Lang_member& Lang_member::
      operator= (Value v)
      {
        static_cast< ::flexisip::Xsd::XmlSchema::String& > (*this) = 
        ::flexisip::Xsd::XmlSchema::String (_xsd_Lang_member_literals_[v]);

        return *this;
      }
    }
  }
}

#include <xsd/cxx/xml/dom/wildcard-source.hxx>

#include <xsd/cxx/xml/dom/parsing-source.hxx>

namespace flexisip
{
  namespace Xsd
  {
    namespace Namespace
    {
      // Lang
      //

      Lang::
      Lang (const ::xercesc::DOMElement& e,
            ::flexisip::Xsd::XmlSchema::Flags f,
            ::flexisip::Xsd::XmlSchema::Container* c)
      : ::flexisip::Xsd::XmlSchema::String (e, f, c)
      {
      }

      Lang::
      Lang (const ::xercesc::DOMAttr& a,
            ::flexisip::Xsd::XmlSchema::Flags f,
            ::flexisip::Xsd::XmlSchema::Container* c)
      : ::flexisip::Xsd::XmlSchema::String (a, f, c)
      {
      }

      Lang::
      Lang (const ::std::string& s,
            const ::xercesc::DOMElement* e,
            ::flexisip::Xsd::XmlSchema::Flags f,
            ::flexisip::Xsd::XmlSchema::Container* c)
      : ::flexisip::Xsd::XmlSchema::String (s, e, f, c)
      {
      }

      Lang* Lang::
      _clone (::flexisip::Xsd::XmlSchema::Flags f,
              ::flexisip::Xsd::XmlSchema::Container* c) const
      {
        return new class Lang (*this, f, c);
      }

      // Space
      //

      Space::
      Space (const ::xercesc::DOMElement& e,
             ::flexisip::Xsd::XmlSchema::Flags f,
             ::flexisip::Xsd::XmlSchema::Container* c)
      : ::flexisip::Xsd::XmlSchema::Ncname (e, f, c)
      {
        _xsd_Space_convert ();
      }

      Space::
      Space (const ::xercesc::DOMAttr& a,
             ::flexisip::Xsd::XmlSchema::Flags f,
             ::flexisip::Xsd::XmlSchema::Container* c)
      : ::flexisip::Xsd::XmlSchema::Ncname (a, f, c)
      {
        _xsd_Space_convert ();
      }

      Space::
      Space (const ::std::string& s,
             const ::xercesc::DOMElement* e,
             ::flexisip::Xsd::XmlSchema::Flags f,
             ::flexisip::Xsd::XmlSchema::Container* c)
      : ::flexisip::Xsd::XmlSchema::Ncname (s, e, f, c)
      {
        _xsd_Space_convert ();
      }

      Space* Space::
      _clone (::flexisip::Xsd::XmlSchema::Flags f,
              ::flexisip::Xsd::XmlSchema::Container* c) const
      {
        return new class Space (*this, f, c);
      }

      Space::Value Space::
      _xsd_Space_convert () const
      {
        ::xsd::cxx::tree::enum_comparator< char > c (_xsd_Space_literals_);
        const Value* i (::std::lower_bound (
                          _xsd_Space_indexes_,
                          _xsd_Space_indexes_ + 2,
                          *this,
                          c));

        if (i == _xsd_Space_indexes_ + 2 || _xsd_Space_literals_[*i] != *this)
        {
          throw ::xsd::cxx::tree::unexpected_enumerator < char > (*this);
        }

        return *i;
      }

      const char* const Space::
      _xsd_Space_literals_[2] =
      {
        "default",
        "preserve"
      };

      const Space::Value Space::
      _xsd_Space_indexes_[2] =
      {
        ::flexisip::Xsd::Namespace::Space::default_,
        ::flexisip::Xsd::Namespace::Space::preserve
      };

      // Lang_member
      //

      Lang_member::
      Lang_member (const ::xercesc::DOMElement& e,
                   ::flexisip::Xsd::XmlSchema::Flags f,
                   ::flexisip::Xsd::XmlSchema::Container* c)
      : ::flexisip::Xsd::XmlSchema::String (e, f, c)
      {
        _xsd_Lang_member_convert ();
      }

      Lang_member::
      Lang_member (const ::xercesc::DOMAttr& a,
                   ::flexisip::Xsd::XmlSchema::Flags f,
                   ::flexisip::Xsd::XmlSchema::Container* c)
      : ::flexisip::Xsd::XmlSchema::String (a, f, c)
      {
        _xsd_Lang_member_convert ();
      }

      Lang_member::
      Lang_member (const ::std::string& s,
                   const ::xercesc::DOMElement* e,
                   ::flexisip::Xsd::XmlSchema::Flags f,
                   ::flexisip::Xsd::XmlSchema::Container* c)
      : ::flexisip::Xsd::XmlSchema::String (s, e, f, c)
      {
        _xsd_Lang_member_convert ();
      }

      Lang_member* Lang_member::
      _clone (::flexisip::Xsd::XmlSchema::Flags f,
              ::flexisip::Xsd::XmlSchema::Container* c) const
      {
        return new class Lang_member (*this, f, c);
      }

      Lang_member::Value Lang_member::
      _xsd_Lang_member_convert () const
      {
        ::xsd::cxx::tree::enum_comparator< char > c (_xsd_Lang_member_literals_);
        const Value* i (::std::lower_bound (
                          _xsd_Lang_member_indexes_,
                          _xsd_Lang_member_indexes_ + 1,
                          *this,
                          c));

        if (i == _xsd_Lang_member_indexes_ + 1 || _xsd_Lang_member_literals_[*i] != *this)
        {
          throw ::xsd::cxx::tree::unexpected_enumerator < char > (*this);
        }

        return *i;
      }

      const char* const Lang_member::
      _xsd_Lang_member_literals_[1] =
      {
        ""
      };

      const Lang_member::Value Lang_member::
      _xsd_Lang_member_indexes_[1] =
      {
        ::flexisip::Xsd::Namespace::Lang_member::empty
      };
    }
  }
}

#include <ostream>

namespace flexisip
{
  namespace Xsd
  {
    namespace Namespace
    {
      ::std::ostream&
      operator<< (::std::ostream& o, const Lang& i)
      {
        return o << static_cast< const ::flexisip::Xsd::XmlSchema::String& > (i);
      }

      ::std::ostream&
      operator<< (::std::ostream& o, Space::Value i)
      {
        return o << Space::_xsd_Space_literals_[i];
      }

      ::std::ostream&
      operator<< (::std::ostream& o, const Space& i)
      {
        return o << static_cast< const ::flexisip::Xsd::XmlSchema::Ncname& > (i);
      }

      ::std::ostream&
      operator<< (::std::ostream& o, Lang_member::Value i)
      {
        return o << Lang_member::_xsd_Lang_member_literals_[i];
      }

      ::std::ostream&
      operator<< (::std::ostream& o, const Lang_member& i)
      {
        return o << static_cast< const ::flexisip::Xsd::XmlSchema::String& > (i);
      }
    }
  }
}

#include <istream>
#include <xsd/cxx/xml/sax/std-input-source.hxx>
#include <xsd/cxx/tree/error-handler.hxx>

namespace flexisip
{
  namespace Xsd
  {
    namespace Namespace
    {
    }
  }
}

#include <ostream>
#include <xsd/cxx/tree/error-handler.hxx>
#include <xsd/cxx/xml/dom/serialization-source.hxx>

namespace flexisip
{
  namespace Xsd
  {
    namespace Namespace
    {
      void
      operator<< (::xercesc::DOMElement& e, const Lang& i)
      {
        e << static_cast< const ::flexisip::Xsd::XmlSchema::String& > (i);
      }

      void
      operator<< (::xercesc::DOMAttr& a, const Lang& i)
      {
        a << static_cast< const ::flexisip::Xsd::XmlSchema::String& > (i);
      }

      void
      operator<< (::flexisip::Xsd::XmlSchema::ListStream& l,
                  const Lang& i)
      {
        l << static_cast< const ::flexisip::Xsd::XmlSchema::String& > (i);
      }

      void
      operator<< (::xercesc::DOMElement& e, const Space& i)
      {
        e << static_cast< const ::flexisip::Xsd::XmlSchema::Ncname& > (i);
      }

      void
      operator<< (::xercesc::DOMAttr& a, const Space& i)
      {
        a << static_cast< const ::flexisip::Xsd::XmlSchema::Ncname& > (i);
      }

      void
      operator<< (::flexisip::Xsd::XmlSchema::ListStream& l,
                  const Space& i)
      {
        l << static_cast< const ::flexisip::Xsd::XmlSchema::Ncname& > (i);
      }

      void
      operator<< (::xercesc::DOMElement& e, const Lang_member& i)
      {
        e << static_cast< const ::flexisip::Xsd::XmlSchema::String& > (i);
      }

      void
      operator<< (::xercesc::DOMAttr& a, const Lang_member& i)
      {
        a << static_cast< const ::flexisip::Xsd::XmlSchema::String& > (i);
      }

      void
      operator<< (::flexisip::Xsd::XmlSchema::ListStream& l,
                  const Lang_member& i)
      {
        l << static_cast< const ::flexisip::Xsd::XmlSchema::String& > (i);
      }
    }
  }
}

#include <xsd/cxx/post.hxx>

// Begin epilogue.
//
#if __clang__ || __GNUC__ >= 4
	#pragma GCC diagnostic pop
#endif
//
// End epilogue.

