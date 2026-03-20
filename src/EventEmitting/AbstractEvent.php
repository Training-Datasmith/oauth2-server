<?php

declare (strict_types=1);
namespace League\O_Auth2\Server\Event_Emitting;

use League\Event\Has_Event_Name;
use Psr\Event_Dispatcher\Stoppable_Event_Interface;
class Abstract_Event implements Stoppable_Event_Interface, Has_Event_Name
{
    private bool $propagation_stopped = false;
    public function __construct(private readonly string $name)
    {
    }
    public function event_name(): string
    {
        return $this->name;
    }
    /**
     * Backwards compatibility method
     *
     * @deprecated use eventName instead
     */
    public function get_name(): string
    {
        return $this->name;
    }
    public function is_propagation_stopped(): bool
    {
        return $this->propagation_stopped;
    }
    public function stop_propagation(): self
    {
        $this->propagation_stopped = true;
        return $this;
    }
}