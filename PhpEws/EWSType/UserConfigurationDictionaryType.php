<?php
/**
 * Definition of the UserConfigurationDictionaryType type
 *
 * @package php-ews
 * @subpackage Types
 */

namespace PhpEws\EWSType;

use PhpEws\EWSType\EWSType;

/**
 * Definition of the UserConfigurationDictionaryType type
 */
class UserConfigurationDictionaryType extends EWSType
{
    /**
     * DictionaryEntry property
     *
     * @var PhpEws\EWSType\UserConfigurationDictionaryEntryType
     */
    public $DictionaryEntry;
}
