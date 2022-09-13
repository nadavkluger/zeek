// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Desc.h"
#include "zeek/IPAddr.h"
#include "zeek/RE.h"
#include "zeek/script_opt/ZAM/BuiltInSupport.h"

namespace zeek::detail
	{

FixedCatArg::FixedCatArg(const TypePtr& _t, int _slot)
: t(_t), slot(_slot)
	{
	switch ( t->Tag() ) {
        TYPE_BOOL:
		max_size = 1;
		break;

        TYPE_INT:
		max_size = 20;	// sufficient for 64 bits
		break;

        TYPE_COUNT:
		max_size = 20;	// sufficient for 64 bits
		break;

        TYPE_DOUBLE:
        TYPE_TIME:
		max_size = 32;	// from modp_dtoa2 documentatino
		break;

        TYPE_ENUM:
		{
		size_t n = 0;
		for ( auto e : t->AsEnumType()->Names() )
			n += e.first.size();
		max_size = n;
		break;
		}

        TYPE_PORT:
		max_size = 5 + 1 + 7;	// <number> + / + "unknown
		break;

        TYPE_ADDR:
		max_size = 39;	// for IPv6
		break;

        TYPE_SUBNET:
		max_size = 39 + 1 + 3;	// for IPv6 + / + <3-digits>
		break;

	default:
		reporter->InternalError("bad type in FixedCatArg constructor");
	}
	}

void FixedCatArg::RenderInto(ZVal* zframe, char*& res)
	{
	auto& z = zframe[slot];
	int n;
	const char* text;
	std::string str;

	switch ( t->Tag() ) {
        TYPE_BOOL:
		*(res++) = z.AsInt() ? 'T' : 'F';
		break;

        TYPE_INT:
		n = modp_litoa10(z.AsInt(), res);
		res += n;
		break;

        TYPE_COUNT:
		n = modp_ulitoa10(z.AsCount(), res);
		res += n;
		break;

        TYPE_DOUBLE:
        TYPE_TIME:
		n = modp_dtoa2(z.AsDouble(), res, 6);
		res += n;
		break;

        TYPE_PATTERN:
		text = z.AsPattern()->AsPattern()->PatternText();
		*(res++) = '/';
		strcpy(res, text);
		res += strlen(text);
		*(res++) = '/';
		break;

        TYPE_ENUM:
		text = t->AsEnumType()->Lookup(z.AsInt());
		strcpy(res, text);
		res += strlen(text);
		break;

        TYPE_PORT:
		{
		uint32_t full_p = static_cast<uint32_t>(z.AsCount());
		zeek_uint_t p = full_p & ~PORT_SPACE_MASK;
		n = modp_ulitoa10(p, res);
		res += n;

		if ( (full_p & TCP_PORT_MASK) == TCP_PORT_MASK )
			{
			strcpy(res, "/tcp");
			res += 4;
			}

		else if ( (full_p & UDP_PORT_MASK) == UDP_PORT_MASK )
			{
			strcpy(res, "/udp");
			res += 4;
			}

		else if ( (full_p & ICMP_PORT_MASK) == ICMP_PORT_MASK )
			{
			strcpy(res, "/icmp");
			res += 5;
			}

		else
			{
			strcpy(res, "/unknown");
			res += 8;
			}

		break;
		}

        TYPE_ADDR:
		str = z.AsAddr()->Get().AsString();
		strcpy(res, str.c_str());
		res += strlen(str.c_str());
		break;

        TYPE_SUBNET:
		str = z.AsSubNet()->Get().AsString();
		strcpy(res, str.c_str());
		res += strlen(str.c_str());
		break;

	default:
		reporter->InternalError("bad type in FixedCatArg::RenderInto");
	}
	}

size_t PatternCatArg::ComputeMaxSize(ZVal* zframe)
	{
	text = zframe[slot].AsPattern()->AsPattern()->PatternText();
	n = strlen(text);
	return n;
	}

	} // zeek::detail
