package identity

import (
	"errors"
	"strings"
)

var (
	UnbalancedTemplatingCharacterErr = errors.New("unbalanced templating characters")
	NoEntityAttachedToToken          = errors.New("string contains entity template directives but no entity was provided")
	NoGroupsAttachedToToken          = errors.New("string contains groups template directives but no groups were provided")
	TemplateValueNotFound            = errors.New("no value could be found for one of the template directives")
)

type PopulateStringInput struct {
	ValidityCheckOnly bool
	String            string
	Entity            *Entity
	Groups            []*Group
}

func PopulateString(p *PopulateStringInput) (bool, string, error) {
	if p == nil {
		return false, "", errors.New("nil input")
	}

	if p.String == "" {
		return false, "", nil
	}

	var subst bool
	splitStr := strings.Split(p.String, "{{")

	if len(splitStr) >= 1 {
		if strings.Index(splitStr[0], "}}") != -1 {
			return false, "", UnbalancedTemplatingCharacterErr
		}
		if len(splitStr) == 1 {
			return false, p.String, nil
		}
	}

	var b strings.Builder
	if !p.ValidityCheckOnly {
		b.Grow(2 * len(p.String))
	}

	for i, str := range splitStr {
		if i == 0 {
			if !p.ValidityCheckOnly {
				b.WriteString(str)
			}
			continue
		}
		splitPiece := strings.Split(str, "}}")
		switch len(splitPiece) {
		case 2:
			subst = true
			if !p.ValidityCheckOnly {
				tmplStr, err := performTemplating(strings.TrimSpace(splitPiece[0]), p.Entity, p.Groups)
				if err != nil {
					return false, "", err
				}
				b.WriteString(tmplStr)
				b.WriteString(splitPiece[1])
			}
		default:
			return false, "", UnbalancedTemplatingCharacterErr
		}
	}

	return subst, b.String(), nil
}

func performTemplating(input string, entity *Entity, groups []*Group) (string, error) {
	performAliasTemplating := func(trimmed string, alias *Alias) (string, error) {
		switch {
		case trimmed == "id":
			return alias.ID, nil
		case trimmed == "name":
			if alias.Name == "" {
				return "", TemplateValueNotFound
			}
			return alias.Name, nil
		case strings.HasPrefix(trimmed, "metadata."):
			val, ok := alias.Metadata[strings.TrimPrefix(trimmed, "metadata.")]
			if !ok {
				return "", TemplateValueNotFound
			}
			return val, nil
		}

		return "", TemplateValueNotFound
	}

	performEntityTemplating := func(trimmed string) (string, error) {
		switch {
		case trimmed == "id":
			return entity.ID, nil
		case trimmed == "name":
			if entity.Name == "" {
				return "", TemplateValueNotFound
			}
			return entity.Name, nil
		case strings.HasPrefix(trimmed, "metadata."):
			val, ok := entity.Metadata[strings.TrimPrefix(trimmed, "metadata.")]
			if !ok {
				return "", TemplateValueNotFound
			}
			return val, nil
		case strings.HasPrefix(trimmed, "aliases."):
			split := strings.SplitN(strings.TrimPrefix(trimmed, "aliases."), ".", 2)
			if len(split) != 2 {
				return "", errors.New("invalid alias selector")
			}
			var found *Alias
			for _, alias := range entity.Aliases {
				if split[0] == alias.MountAccessor {
					found = alias
					break
				}
			}
			if found == nil {
				return "", errors.New("alias not found")
			}
			return performAliasTemplating(split[1], found)
		}

		return "", TemplateValueNotFound
	}

	performGroupsTemplating := func(trimmed string) (string, error) {
		var ids bool

		selectorSplit := strings.SplitN(trimmed, ".", 2)
		switch {
		case len(selectorSplit) != 2:
			return "", errors.New("invalid groups selector")
		case selectorSplit[0] == "ids":
			ids = true
		case selectorSplit[0] == "names":
		default:
			return "", errors.New("invalid groups selector")
		}
		trimmed = selectorSplit[1]

		accessorSplit := strings.SplitN(trimmed, ".", 2)
		if len(accessorSplit) != 2 {
			return "", errors.New("invalid groups accessor")
		}
		var found *Group
		for _, group := range groups {
			if ids && group.ID == accessorSplit[0] {
				found = group
				break
			}
			if group.Name == accessorSplit[0] {
				found = group
				break
			}
		}

		if found == nil {
			return "", errors.New("group not found")
		}

		trimmed = accessorSplit[1]

		switch {
		case trimmed == "id":
			return found.ID, nil
		case trimmed == "name":
			if found.Name == "" {
				return "", TemplateValueNotFound
			}
			return found.Name, nil
		case strings.HasPrefix(trimmed, "metadata."):
			val, ok := found.Metadata[strings.TrimPrefix(trimmed, "metadata.")]
			if !ok {
				return "", TemplateValueNotFound
			}
			return val, nil
		}

		return "", TemplateValueNotFound
	}

	switch {
	case strings.HasPrefix(input, "identity.entity."):
		if entity == nil {
			return "", NoEntityAttachedToToken
		}
		return performEntityTemplating(strings.TrimPrefix(input, "identity.entity."))

	case strings.HasPrefix(input, "identity.groups."):
		if len(groups) == 0 {
			return "", NoGroupsAttachedToToken
		}
		return performGroupsTemplating(strings.TrimPrefix(input, "identity.groups."))
	}

	return "", TemplateValueNotFound
}
