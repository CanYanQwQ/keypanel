<?php

namespace App\Services;

use App\Enums\ApiErrorCode;

class CardKeyException extends \RuntimeException
{
    public function __construct(public readonly ApiErrorCode $errorCode)
    {
        parent::__construct($errorCode->message(), $errorCode->value);
    }
}